// Real proxy/session model; only user discovery and the daemon socket peer are synthetic.
// SPDX-License-Identifier: GPL-2.0-or-later
#include "Configuration.h"
#include "GreeterProxy.h"
#include "Messages.h"
#include "ScreenModel.h"
#include "SessionModel.h"
#include "ThemeConfig.h"
#include <QAbstractListModel>
#include <QDataStream>
#include <QFile>
#include <QGuiApplication>
#include <QImage>
#include <QLocalServer>
#include <QLocalSocket>
#include <QQmlContext>
#include <QQmlEngine>
#include <QQuickItem>
#include <QQuickView>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <memory>

using namespace SDDM;

class Users : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int count READ rowCount CONSTANT)
    Q_PROPERTY(int lastIndex READ lastIndex CONSTANT)
public:
    int rowCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : 2; }
    int lastIndex() const { return 0; }
    QHash<int, QByteArray> roleNames() const override {
        return {{Qt::UserRole + 1, "name"}, {Qt::UserRole + 2, "realName"}};
    }
    QVariant data(const QModelIndex &index, int role) const override {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) return {};
        if (role == Qt::UserRole + 1) return index.row() == 0 ? "alice" : "bob";
        if (role == Qt::UserRole + 2) return index.row() == 0 ? "Alice Display Name" : "Bob Display Name";
        return {};
    }
};

// Deliberately lacks ALL method/context properties, slots and controller context.
class StockProxy : public QObject {
    Q_OBJECT
public:
    QString user;
    int session = -1;
    int submissions = 0;
    Q_INVOKABLE void login(const QString &name, const QString &, int index) {
        user = name;
        session = index;
        ++submissions;
    }
signals:
    void loginFailed();
    void loginSucceeded();
};

class ThemeContextTest : public QObject {
    Q_OBJECT
    struct Frame {
        GreeterMessages opcode;
        quint64 serial = 0;
        quint32 flag = 0;
        QString user, password, request;
        Session session;
    };
    QTemporaryDir temporary;
    QLocalServer server;
    std::unique_ptr<QLocalSocket> peer;
    std::unique_ptr<SessionModel> sessions;
    std::unique_ptr<GreeterProxy> proxy;
    std::unique_ptr<QQuickView> view;
    Users users;
    QList<Frame> frames;
    QString original, adapted;

    void receive() {
        QDataStream in(peer.get());
        while (peer->bytesAvailable()) {
            in.startTransaction();
            quint32 opcode;
            in >> opcode;
            Frame frame;
            frame.opcode = GreeterMessages(opcode);
            switch (frame.opcode) {
            case GreeterMessages::Connect:
            case GreeterMessages::QueryAuthenticationCapabilities: break;
            case GreeterMessages::SetAuthenticationContext:
                in >> frame.serial >> frame.flag;
                if (frame.flag) in >> frame.user >> frame.session;
                break;
            case GreeterMessages::StartAuthenticationMethod: in >> frame.serial >> frame.flag; break;
            case GreeterMessages::CancelAuthenticationMethod: in >> frame.serial >> frame.request >> frame.flag; break;
            case GreeterMessages::Login: in >> frame.user >> frame.password >> frame.session; break;
            default: QFAIL("Unexpected client opcode");
            }
            if (!in.commitTransaction()) return;
            frames.append(frame);
        }
    }
    template<class Writer> void send(Writer writer) {
        QByteArray bytes;
        QDataStream out(&bytes, QIODevice::WriteOnly);
        writer(out);
        peer->write(bytes);
        peer->flush();
    }
    int count(GreeterMessages opcode) const {
        int result = 0;
        for (const auto &frame : frames) if (frame.opcode == opcode) ++result;
        return result;
    }
    Frame latestContext() const {
        for (auto i = frames.crbegin(); i != frames.crend(); ++i)
            if (i->opcode == GreeterMessages::SetAuthenticationContext) return *i;
        return Frame();
    }
    QQuickItem *password(QQuickView &target) const {
        for (auto item : target.rootObject()->findChildren<QQuickItem *>())
            if (item->inherits("QQuickTextInput")) return item;
        return nullptr;
    }
    void load(QQuickView &target, QObject *greeter, const QString &path, bool controller, bool extensions = true) {
        target.rootContext()->setContextProperty("sddm", greeter);
        target.rootContext()->setContextProperty("userModel", &users);
        target.rootContext()->setContextProperty("sessionModel", sessions.get());
        target.rootContext()->setContextProperty("screenModel", new ScreenModel(QGuiApplication::primaryScreen(), &target));
        target.rootContext()->setContextProperty("config", new ThemeConfig(original + "/theme.conf", &target));
        if (extensions) target.rootContext()->setContextProperty("authenticationController", controller);
        target.setResizeMode(QQuickView::SizeRootObjectToView);
        target.resize(1024, 768);
        target.setSource(QUrl::fromLocalFile(path + "/Main.qml"));
        QCOMPARE(target.status(), QQuickView::Ready);
        target.show();
        QTRY_VERIFY(target.isExposed());
        QVERIFY(password(target));
    }
    void capabilities() {
        send([](QDataStream &out) { out << quint32(DaemonMessages::AuthenticationCapabilities) << quint32(2); });
        QTRY_VERIFY(proxy->authenticationMethodsAvailable());
    }
    void setup(bool methods = true, bool controller = true) {
        QVERIFY(temporary.isValid());
        for (const auto &name : {"alpha", "beta"}) {
            QFile file(temporary.filePath(QString(name) + ".desktop"));
            QVERIFY(file.open(QIODevice::WriteOnly));
            file.write("[Desktop Entry]\nName=Desktop\nExec=/bin/true\nTryExec=/bin/true\nType=Application\n");
        }
        mainConfig.X11.SessionDir.set({temporary.path()});
        mainConfig.Wayland.SessionDir.set({temporary.path()});
        sessions = std::make_unique<SessionModel>();
        QVERIFY(sessions->rowCount() > 1);
        QVERIFY(server.listen(temporary.filePath("socket")));
        proxy = std::make_unique<GreeterProxy>(server.fullServerName());
        proxy->setSessionModel(sessions.get());
        proxy->setAuthenticationController(controller);
        QTRY_VERIFY(server.hasPendingConnections());
        peer.reset(server.nextPendingConnection());
        connect(peer.get(), &QLocalSocket::readyRead, this, &ThemeContextTest::receive);
        receive();
        QTRY_COMPARE(count(GreeterMessages::QueryAuthenticationCapabilities), 1);
        if (methods) capabilities();
        view = std::make_unique<QQuickView>();
        load(*view, proxy.get(), adapted, controller);
    }
    void acknowledge(AuthenticationPhase phase = AuthenticationPhase::Idle) {
        const auto frame = latestContext();
        QVERIFY(frame.flag == 1);
        send([&](QDataStream &out) {
            out << quint32(DaemonMessages::AuthenticationContext) << frame.serial << quint32(1)
                << QStringLiteral("11111111-1111-4111-8111-111111111111") << frame.user << frame.session
                << quint32(AuthenticationAvailability::Available) << quint32(phase) << QStringLiteral("available");
        });
        QTRY_VERIFY(!proxy->fingerprintRequestId().isEmpty());
    }
    void submit(QQuickView &target, const QString &text = "synthetic-test-input") {
        QVERIFY(password(target)->setProperty("text", text));
        QVERIFY(QMetaObject::invokeMethod(password(target), "accepted"));
    }
private slots:
    void initTestCase() {
        original = qEnvironmentVariable("THEME_CONTEXT_ORIGINAL");
        adapted = qEnvironmentVariable("THEME_CONTEXT_ADAPTED");
        QVERIFY(!original.isEmpty() && !adapted.isEmpty());
    }
    void cleanup() {
        QCoreApplication::processEvents();
        // This gate publishes selection only; it must NEVER start authentication.
        QCOMPARE(count(GreeterMessages::StartAuthenticationMethod), 0);
        view.reset();
        proxy.reset();
        peer.reset();
        sessions.reset();
        server.close();
        frames.clear();
    }
    void publishesLoginNameBeforeEnter() {
        setup();
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        QCOMPARE(latestContext().user, QStringLiteral("alice"));
        QCOMPARE(view->rootObject()->property("currentUsername").toString(), QStringLiteral("Alice Display Name"));
        QCOMPARE(count(GreeterMessages::Login), 0);
        QCOMPARE(latestContext().session.fileName(), sessions->sessionAt(view->rootObject()->property("currentSessionsIndex").toInt()).fileName());
    }
    void lateCapabilitiesPublishCurrentSelection() {
        setup(false);
        QVERIFY(view->rootObject()->setProperty("currentUsersIndex", 1));
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), 0);
        capabilities();
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        QCOMPARE(latestContext().user, QStringLiteral("bob"));
    }
    void switchesPublishExactTargetAndClearPassword() {
        setup();
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        const auto firstSerial = latestContext().serial;
        password(*view)->setProperty("text", "synthetic-old-input");
        QVERIFY(QMetaObject::invokeMethod(view->rootObject(), "usersCycleSelectNext"));
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 2);
        QCOMPARE(latestContext().user, QStringLiteral("bob"));
        QVERIFY(latestContext().serial > firstSerial);
        QCOMPARE(password(*view)->property("text").toString(), QString());
        password(*view)->setProperty("text", "synthetic-old-input");
        QVERIFY(QMetaObject::invokeMethod(view->rootObject(), "sessionsCycleSelectNext"));
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 3);
        QCOMPARE(latestContext().session.fileName(), sessions->sessionAt(view->rootObject()->property("currentSessionsIndex").toInt()).fileName());
        QCOMPARE(password(*view)->property("text").toString(), QString());
        submit(*view);
        QTRY_COMPARE(count(GreeterMessages::Login), 1);
        QCOMPARE(frames.last().user, QStringLiteral("bob"));
        QCOMPARE(frames.last().session.fileName(), latestContext().session.fileName());
    }
    void invalidSelectionClearsAndNeverInventsAccount_data() {
        QTest::addColumn<QByteArray>("property");
        QTest::newRow("user") << QByteArray("currentUsersIndex");
        QTest::newRow("session") << QByteArray("currentSessionsIndex");
    }
    void invalidSelectionClearsAndNeverInventsAccount() {
        QFETCH(QByteArray, property);
        setup();
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        QVERIFY(view->rootObject()->setProperty(property.constData(), -1));
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 2);
        QCOMPARE(latestContext().flag, quint32(0));
        submit(*view);
        QCoreApplication::processEvents();
        QCOMPARE(count(GreeterMessages::Login), 0);
        const auto clear = latestContext();
        QVERIFY(view->rootObject()->setProperty(property.constData(), 0));
        QCoreApplication::processEvents();
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), 2); // Clear barrier still pending.
        send([&](QDataStream &out) {
            out << quint32(DaemonMessages::AuthenticationContext) << clear.serial << quint32(1)
                << QString() << QString() << Session()
                << quint32(AuthenticationAvailability::Unavailable) << quint32(AuthenticationPhase::Idle)
                << QStringLiteral("cleared");
        });
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 3);
        QCOMPARE(latestContext().user, QStringLiteral("alice"));
        QVERIFY(latestContext().serial > clear.serial);
    }
    void stockDaemonPasswordStillWorks() {
        setup(false);
        submit(*view);
        QTRY_COMPARE(count(GreeterMessages::Login), 1);
        QCOMPARE(frames.last().user, QStringLiteral("alice"));
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), 0);
    }
    void stockApiWithoutExtensionsStillWorks() {
        setup(false);
        view.reset();
        StockProxy stock;
        QQuickView target;
        load(target, &stock, adapted, false, false);
        submit(target);
        QCOMPARE(stock.submissions, 1);
        QCOMPARE(stock.user, QStringLiteral("alice"));
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), 0);
    }
    void mirrorHideAndDestructionNeverClearOwner() {
        setup();
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        {
            QQuickView mirror;
            load(mirror, proxy.get(), adapted, false);
            mirror.rootObject()->setProperty("currentUsersIndex", 1);
            mirror.hide();
            QCoreApplication::processEvents();
        }
        QCoreApplication::processEvents();
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        QCOMPARE(latestContext().user, QStringLiteral("alice"));
    }
    void controllingHideClearsContext() {
        setup();
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        view->hide();
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 2);
        QCOMPARE(latestContext().flag, quint32(0));
    }
    void committedSelectionCannotBeCycledOrSubmitted() {
        setup();
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        acknowledge(AuthenticationPhase::SessionAuthorized);
        QTRY_VERIFY(proxy->authenticationBusy());
        const auto user = view->rootObject()->property("currentUsersIndex");
        const auto session = view->rootObject()->property("currentSessionsIndex");
        QVERIFY(QMetaObject::invokeMethod(view->rootObject(), "usersCycleSelectNext"));
        QVERIFY(QMetaObject::invokeMethod(view->rootObject(), "sessionsCycleSelectNext"));
        QCOMPARE(view->rootObject()->property("currentUsersIndex"), user);
        QCOMPARE(view->rootObject()->property("currentSessionsIndex"), session);
        submit(*view);
        QCoreApplication::processEvents();
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        QCOMPARE(count(GreeterMessages::Login), 0);
    }
    void unchangedSurfacePixelsAndGeometry_data() {
        QTest::addColumn<QString>("input");
        QTest::newRow("empty") << QString();
        QTest::newRow("masked-synthetic") << QStringLiteral("visual-fixture");
    }
    void unchangedSurfacePixelsAndGeometry() {
        QFETCH(QString, input);
        setup(false);
        const QRectF adaptedBounds(password(*view)->position(), password(*view)->size());
        // No real credentials: known synthetic text on an isolated mock-daemon surface.
        password(*view)->setProperty("text", input);
        // Hide the naturally blinking cursor in BOTH roots for deterministic comparison.
        password(*view)->setProperty("cursorVisible", false);
        QTest::qWait(100);
        const QImage after = view->grabWindow();
        QVERIFY(!after.isNull());
        view->hide();
        QQuickView baseline;
        load(baseline, proxy.get(), original, true);
        password(baseline)->setProperty("text", input);
        password(baseline)->setProperty("cursorVisible", false);
        QTest::qWait(100);
        const QImage before = baseline.grabWindow();
        QVERIFY(!before.isNull());
        QCOMPARE(QRectF(password(baseline)->position(), password(baseline)->size()), adaptedBounds);
        QCOMPARE(before, after);
        const auto evidence = qEnvironmentVariable("THEME_CONTEXT_EVIDENCE");
        QVERIFY(!evidence.isEmpty());
        const QString suffix = QString::fromLatin1(QTest::currentDataTag()) + QStringLiteral(".png");
        QVERIFY(before.save(evidence + "/original-" + suffix));
        QVERIFY(after.save(evidence + "/adapted-" + suffix));
    }
};

QTEST_MAIN(ThemeContextTest)
#include "ThemeContextTest.moc"
