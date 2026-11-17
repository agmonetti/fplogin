// SPDX-License-Identifier: GPL-2.0-or-later
// Actual theme, policy, proxy and session model; no real daemon, PAM or reader.
#include "Configuration.h"
#include "GreeterProxy.h"
#include "Messages.h"
#include "ScreenModel.h"
#include "SessionModel.h"
#include "ThemeAuthentication.h"
#include "ThemeConfig.h"
#include <QAbstractListModel>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QGuiApplication>
#include <QImage>
#include <QLocalServer>
#include <QLocalSocket>
#include <QQmlContext>
#include <QQuickItem>
#include <QQuickView>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <memory>
using namespace SDDM;

class Users : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int count READ rowCount NOTIFY changed)
    Q_PROPERTY(int lastIndex MEMBER lastIndex NOTIFY changed)
public:
    QStringList names {"alice", "bob"};
    int lastIndex = 0;
    int rowCount(const QModelIndex &p = {}) const override { return p.isValid() ? 0 : names.size(); }
    QHash<int, QByteArray> roleNames() const override {
        return {{Qt::UserRole + 1, "name"}, {Qt::UserRole + 2, "realName"}};
    }
    QVariant data(const QModelIndex &i, int role) const override {
        if (!i.isValid() || i.row() >= names.size()) return {};
        if (role == Qt::UserRole + 1) return names[i.row()];
        if (role == Qt::UserRole + 2) return names[i.row()] + " Display Name";
        return {};
    }
    void reset(const QStringList &next) { beginResetModel(); names = next; endResetModel(); emit changed(); }
    void rename(int index, const QString &name) { names[index] = name; emit dataChanged(this->index(index), this->index(index)); }
signals:
    void changed();
};
class Sessions : public SessionModel {
public:
    void resetUnchanged() { beginResetModel(); endResetModel(); }
};
class StockProxy : public QObject {
    Q_OBJECT
public:
    int submissions = 0;
    Q_INVOKABLE void login(const QString &, const QString &, int) { ++submissions; }
signals:
    void loginFailed();
    void loginSucceeded();
};
class ThemeAutoTest : public QObject {
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
    std::unique_ptr<Sessions> sessions;
    std::unique_ptr<GreeterProxy> proxy;
    std::unique_ptr<ThemeAuthentication> policy;
    std::unique_ptr<QQuickView> view;
    Users users;
    QList<Frame> frames;
    QString original, adapted;
    bool decodeError = false;

    void receive() {
        QDataStream in(peer.get());
        while (peer->bytesAvailable()) {
            in.startTransaction();
            quint32 opcode;
            in >> opcode;
            Frame f;
            f.opcode = GreeterMessages(opcode);
            switch (f.opcode) {
            case GreeterMessages::Connect:
            case GreeterMessages::QueryAuthenticationCapabilities: break;
            case GreeterMessages::SetAuthenticationContext:
                in >> f.serial >> f.flag;
                if (f.flag) in >> f.user >> f.session;
                break;
            case GreeterMessages::StartAuthenticationMethod: in >> f.serial >> f.flag; break;
            case GreeterMessages::CancelAuthenticationMethod: in >> f.serial >> f.request >> f.flag; break;
            case GreeterMessages::Login: in >> f.user >> f.password >> f.session; break;
            default: decodeError = true; in.abortTransaction(); return;
            }
            if (!in.commitTransaction()) return;
            frames.append(f);
        }
    }
    template<class Writer> void send(Writer writer) {
        QByteArray bytes;
        QDataStream out(&bytes, QIODevice::WriteOnly);
        writer(out);
        peer->write(bytes); peer->flush();
    }
    int count(GreeterMessages opcode) const {
        int n = 0;
        for (const auto &f : frames) if (f.opcode == opcode) ++n;
        return n;
    }
    int starts() const { return count(GreeterMessages::StartAuthenticationMethod); }
    Frame context() const {
        for (auto i = frames.crbegin(); i != frames.crend(); ++i)
            if (i->opcode == GreeterMessages::SetAuthenticationContext) return *i;
        return Frame();
    }
    QString request(const Frame &f) const {
        return QStringLiteral("11111111-1111-4111-8111-%1").arg(f.serial, 12, 10, QLatin1Char('0'));
    }
    void acknowledge(const Frame &f, bool available = true, AuthenticationPhase phase = AuthenticationPhase::Idle,
                     bool accepted = true) {
        send([&](QDataStream &out) {
            out << quint32(DaemonMessages::AuthenticationContext) << f.serial << quint32(accepted)
                << (f.flag ? request(f) : QString()) << f.user << f.session
                << quint32(available ? AuthenticationAvailability::Available : AuthenticationAvailability::Unavailable)
                << quint32(phase) << (accepted ? (f.flag ? QStringLiteral("available") : QStringLiteral("cleared"))
                                               : QStringLiteral("session_committed"));
        });
    }
    void state(const Frame &f, FingerprintState state, AuthenticationPhase phase = AuthenticationPhase::Active) {
        send([&](QDataStream &out) {
            out << quint32(DaemonMessages::AuthenticationMethodState) << f.serial << request(f)
                << quint32(AuthenticationMethod::Fingerprint) << f.user << f.session
                << quint32(state) << quint32(phase) << QStringLiteral("test_state");
        });
    }
    void finish(const Frame &f, AuthenticationResult result, AuthenticationMethod method = AuthenticationMethod::NoWinner) {
        send([&](QDataStream &out) {
            out << quint32(DaemonMessages::AuthenticationAttemptFinished) << f.serial << request(f)
                << f.user << f.session << quint32(result) << quint32(method);
        });
    }
    QQuickItem *password(QQuickView &v) const {
        for (auto item : v.rootObject()->findChildren<QQuickItem *>())
            if (item->inherits("QQuickTextInput")) return item;
        return nullptr;
    }
    void load(QQuickView &v, QObject *greeter, const QString &path, bool controller, bool show = true,
              bool extensions = true) {
        v.rootContext()->setContextProperty("sddm", greeter);
        v.rootContext()->setContextProperty("userModel", &users);
        v.rootContext()->setContextProperty("sessionModel", sessions.get());
        v.rootContext()->setContextProperty("screenModel", new ScreenModel(QGuiApplication::primaryScreen(), &v));
        v.rootContext()->setContextProperty("config", new ThemeConfig(original + "/theme.conf", &v));
        if (extensions) {
            v.rootContext()->setContextProperty("authenticationController", controller);
            v.rootContext()->setContextProperty("themeAuthentication", policy.get());
        }
        v.setResizeMode(QQuickView::SizeRootObjectToView);
        v.resize(1024, 768);
        v.setSource(QUrl::fromLocalFile(path + "/Main.qml"));
        QCOMPARE(v.status(), QQuickView::Ready);
        QVERIFY(password(v));
        if (show) { v.show(); QTRY_VERIFY(v.isExposed()); }
    }
    void capabilities() {
        send([](QDataStream &out) { out << quint32(DaemonMessages::AuthenticationCapabilities) << quint32(2); });
        QTRY_VERIFY(proxy->authenticationMethodsAvailable());
    }
    bool writeSession(const QString &file) {
        QFile f(temporary.filePath("sessions/" + file));
        const QByteArray contents("[Desktop Entry]\nName=Desktop\nExec=/bin/true\nTryExec=/bin/true\nType=Application\n");
        return f.open(QIODevice::WriteOnly) && f.write(contents) == contents.size();
    }
    bool changeSessionFile(const QString &file, bool present) {
        auto watcher = sessions->findChild<QFileSystemWatcher *>();
        if (!watcher) return false;
        const auto paths = watcher->directories();
        if (paths.isEmpty()) return false;
        // Drive the production reload once, without a duplicate queued filesystem notification.
        if (!watcher->removePaths(paths).isEmpty()) return false;
        const bool changed = present ? writeSession(file) : QFile::remove(temporary.filePath("sessions/" + file));
        const bool watched = watcher->addPaths(paths).isEmpty();
        return changed && watched && QMetaObject::invokeMethod(watcher, "directoryChanged", Qt::DirectConnection,
                                                              Q_ARG(QString, paths.first()));
    }
    void setup(bool methods = true, bool show = true) {
        QVERIFY(QDir().mkpath(temporary.filePath("sessions")));
        for (const auto &name : {"alpha", "beta"})
            QVERIFY(writeSession(QString(name) + ".desktop"));
        mainConfig.X11.SessionDir.set({temporary.filePath("sessions")});
        mainConfig.Wayland.SessionDir.set({temporary.filePath("sessions")});
        sessions = std::make_unique<Sessions>();
        QVERIFY(sessions->rowCount() > 1);
        QVERIFY(server.listen(temporary.filePath("socket")));
        proxy = std::make_unique<GreeterProxy>(server.fullServerName());
        proxy->setSessionModel(sessions.get());
        proxy->setAuthenticationController(true);
        QTRY_VERIFY(server.hasPendingConnections());
        peer.reset(server.nextPendingConnection());
        connect(peer.get(), &QLocalSocket::readyRead, this, &ThemeAutoTest::receive);
        receive();
        QTRY_COMPARE(count(GreeterMessages::QueryAuthenticationCapabilities), 1);
        policy = std::make_unique<ThemeAuthentication>(proxy.get(), &users, sessions.get());
        view = std::make_unique<QQuickView>();
        policy->setControllerView(view.get());
        if (methods) capabilities();
        load(*view, proxy.get(), adapted, true, show);
    }
    void start() {
        setup();
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        acknowledge(context());
        QTRY_COMPARE(starts(), 1);
    }
    void submit() { QVERIFY(QMetaObject::invokeMethod(password(*view), "accepted")); }
private slots:
    void initTestCase() {
        original = qEnvironmentVariable("THEME_CONTEXT_ORIGINAL");
        adapted = qEnvironmentVariable("THEME_CONTEXT_ADAPTED");
        QVERIFY(!original.isEmpty() && !adapted.isEmpty());
    }
    void cleanup() {
        QVERIFY(!decodeError);
        if (policy) policy->setControllerView(nullptr);
        view.reset(); policy.reset(); proxy.reset(); peer.reset(); sessions.reset();
        server.close(); frames.clear();
        QVERIFY(QDir(temporary.filePath("sessions")).removeRecursively());
        users.reset({"alice", "bob"}); users.lastIndex = 0;
    }
    void exposedHiddenLabelsStartOnceWithoutEnter() {
        setup(true, false);
        QTest::qWait(30);
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), 0);
        view->show(); QTRY_VERIFY(view->isExposed());
        QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        QCOMPARE(context().user, QStringLiteral("alice"));
        QCOMPARE(starts(), 0); // ACK, not publication, authorizes automatic start.
        const auto f = context(); acknowledge(f);
        QTRY_COMPARE(starts(), 1);
        QCOMPARE(count(GreeterMessages::Login), 0);
        acknowledge(f); acknowledge(f);
        state(f, FingerprintState::Scanning); state(f, FingerprintState::Retry);
        QTest::qWait(50); QCOMPARE(starts(), 1);
    }
    void lateCapabilitiesAndAvailability() {
        setup(false);
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), 0);
        capabilities(); QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        const auto f = context(); acknowledge(f, false);
        QTRY_VERIFY(!proxy->fingerprintRequestId().isEmpty());
        QCOMPARE(starts(), 0);
        acknowledge(f, true); QTRY_COMPARE(starts(), 1);
        acknowledge(f, true); QTest::qWait(20); QCOMPARE(starts(), 1);
    }
    void terminalFingerprintKeepsPassword_data() {
        QTest::addColumn<int>("terminal");
        QTest::newRow("failed") << int(FingerprintState::Failed);
        QTest::newRow("timed-out") << int(FingerprintState::TimedOut);
        QTest::newRow("cancelled") << int(FingerprintState::Cancelled);
        QTest::newRow("unavailable") << int(FingerprintState::Unavailable);
    }
    void terminalFingerprintKeepsPassword() {
        QFETCH(int, terminal);
        start();
        const auto f = context();
        password(*view)->setProperty("text", "synthetic-retained");
        QSignalSpy failed(proxy.get(), &GreeterProxy::loginFailed);
        state(f, FingerprintState(terminal), AuthenticationPhase::Idle);
        finish(f, terminal == int(FingerprintState::Cancelled) ? AuthenticationResult::Cancelled : AuthenticationResult::Failed);
        QTest::qWait(30);
        QCOMPARE(password(*view)->property("text").toString(), QStringLiteral("synthetic-retained"));
        QCOMPARE(failed.size(), 0); QCOMPARE(starts(), 1);
    }
    void escapeThenExplicitF4Retry() {
        start();
        const auto f = context();
        password(*view)->setProperty("text", "synthetic-retained");
        view->requestActivate(); QTest::qWait(50);
        QTest::keyClick(view.get(), Qt::Key_Escape);
        QTRY_COMPARE(count(GreeterMessages::CancelAuthenticationMethod), 1);
        state(f, FingerprintState::Cancelled, AuthenticationPhase::Idle);
        finish(f, AuthenticationResult::Cancelled);
        QTest::qWait(30); QCOMPARE(starts(), 1);
        QCOMPARE(password(*view)->property("text").toString(), QStringLiteral("synthetic-retained"));
        QTest::keyClick(view.get(), Qt::Key_F4);
        QTRY_VERIFY(context().serial > f.serial);
        const auto retry = context(); acknowledge(retry);
        QTRY_COMPARE(starts(), 2);
        state(retry, FingerprintState::Scanning);
        QTest::keyClick(view.get(), Qt::Key_F4);
        QTest::qWait(30); QCOMPARE(starts(), 2);
    }
    void explicitRetryCanProbeUnavailable() {
        setup(); QTRY_COMPARE(count(GreeterMessages::SetAuthenticationContext), 1);
        const auto f = context();
        acknowledge(f, false); QTRY_VERIFY(!proxy->fingerprintRequestId().isEmpty());
        QCOMPARE(starts(), 0);
        policy->retry(view.get()); QTRY_COMPARE(starts(), 1);
        auto probe = [&](AuthenticationAvailability availability, const QString &detail) {
            send([&](QDataStream &out) {
                out << quint32(DaemonMessages::AuthenticationContext) << f.serial << quint32(1)
                    << request(f) << f.user << f.session << quint32(availability)
                    << quint32(AuthenticationPhase::Idle) << detail;
            });
        };
        probe(AuthenticationAvailability::Unknown, QStringLiteral("checking"));
        QTRY_COMPARE(proxy->fingerprintDetailCode(), QStringLiteral("checking"));
        policy->retry(view.get()); QTest::qWait(20); QCOMPARE(starts(), 1);
        probe(AuthenticationAvailability::Unavailable, QStringLiteral("availability_unavailable"));
        QTRY_COMPARE(proxy->fingerprintDetailCode(), QStringLiteral("availability_unavailable"));
        QTest::qWait(20); QCOMPARE(starts(), 1); // Notifications cannot retry.
        policy->retry(view.get()); QTRY_COMPARE(starts(), 2); // Same request, state and availability.
    }
    void hideClearBarrierDoesNotRetry() {
        start();
        view->hide(); QTRY_COMPARE(context().flag, quint32(0));
        const auto clear = context();
        view->show(); QTRY_VERIFY(view->isExposed());
        QTest::qWait(30); QCOMPARE(context().serial, clear.serial); QCOMPARE(starts(), 1);
        acknowledge(clear, false);
        QTRY_VERIFY(context().serial > clear.serial);
        acknowledge(context()); QTest::qWait(30); QCOMPARE(starts(), 1);
    }
    void mirrorDefaultsPromotionAndDestruction() {
        start();
        const auto f = context();
        users.lastIndex = 1;
        auto mirror = std::make_unique<QQuickView>();
        load(*mirror, proxy.get(), adapted, false);
        QCOMPARE(mirror->rootObject()->property("currentUsersIndex").toInt(), 0);
        QVERIFY(!policy->select(mirror.get(), "bob", 0));
        mirror->hide(); QTest::qWait(20);
        QCOMPARE(context().serial, f.serial); QCOMPARE(starts(), 1);
        mirror->show(); QTRY_VERIFY(mirror->isExposed());
        // Same production order: revoke, clear/drain, then promote before QML owner flag.
        policy->setControllerView(nullptr); proxy->setAuthenticationController(false);
        view->rootContext()->setContextProperty("authenticationController", false);
        proxy->clearAuthenticationContext(); QTRY_COMPARE(context().flag, quint32(0));
        const auto clear = context(); acknowledge(clear, false);
        QTRY_VERIFY(proxy->authenticationUser().isEmpty());
        policy->setControllerView(mirror.get()); proxy->setAuthenticationController(true);
        mirror->rootContext()->setContextProperty("authenticationController", true);
        QTRY_VERIFY(context().serial > clear.serial);
        QCOMPARE(context().user, QStringLiteral("alice"));
        acknowledge(context()); QTest::qWait(30); QCOMPARE(starts(), 1);
        view.reset(); QTest::qWait(20); QCOMPARE(context().user, QStringLiteral("alice"));
        policy->setControllerView(nullptr);
        mirror.reset();
    }
    void userResetReorderAndRemovalNeverAdoptDefault() {
        start();
        password(*view)->setProperty("text", "synthetic-retained");
        users.reset({"bob", "alice"});
        QTRY_COMPARE(context().flag, quint32(0));
        const auto clear = context();
        QTRY_COMPARE(policy->userIndex(), 1);
        QCOMPARE(policy->user(), QStringLiteral("alice"));
        QCOMPARE(password(*view)->property("text").toString(), QStringLiteral("synthetic-retained"));
        acknowledge(clear, false);
        QTRY_VERIFY(context().serial > clear.serial);
        acknowledge(context()); QTest::qWait(30); QCOMPARE(starts(), 1);
        sessions->resetUnchanged(); QTRY_COMPARE(context().flag, quint32(0));
        const auto sessionClear = context(); acknowledge(sessionClear, false);
        QTRY_VERIFY(context().serial > sessionClear.serial);
        acknowledge(context()); QTest::qWait(30); QCOMPARE(starts(), 1);
        users.reset({"bob"});
        QTRY_VERIFY(!policy->valid());
        QTRY_COMPARE(context().flag, quint32(0));
        QCOMPARE(password(*view)->property("text").toString(), QString());
        acknowledge(context(), false); QTest::qWait(30);
        QVERIFY(!policy->valid()); QCOMPARE(starts(), 1);
        password(*view)->setProperty("text", "synthetic-input"); submit();
        QTest::qWait(20); QCOMPARE(count(GreeterMessages::Login), 0);
    }
    void sessionReorderPreservesIdentityPasswordAndConsumedStart() {
        start(); const auto selected = context();
        const int oldIndex = policy->sessionIndex();
        password(*view)->setProperty("text", "synthetic-retained");
        QSignalSpy resets(sessions.get(), &QAbstractItemModel::modelReset);
        QVERIFY(changeSessionFile("000-before.desktop", true));
        QCOMPARE(resets.size(), 1);
        const int nextIndex = sessions->indexOfSession(selected.session.type(), selected.session.fileName());
        QVERIFY(nextIndex > oldIndex);
        QCOMPARE(policy->sessionIndex(), nextIndex);
        QCOMPARE(view->rootObject()->property("currentSessionsIndex").toInt(), nextIndex);
        QCOMPARE(password(*view)->property("text").toString(), QStringLiteral("synthetic-retained"));
        QTRY_COMPARE(context().flag, quint32(0)); const auto clear = context();
        QTest::qWait(30); QCOMPARE(context().serial, clear.serial); QCOMPARE(starts(), 1);
        acknowledge(clear, false); QTRY_VERIFY(context().serial > clear.serial);
        const auto restored = context();
        QCOMPARE(restored.user, selected.user);
        QCOMPARE(restored.session.type(), selected.session.type());
        QCOMPARE(restored.session.fileName(), selected.session.fileName());
        acknowledge(restored); QTRY_COMPARE(proxy->authenticationSessionIndex(), nextIndex);
        QTest::qWait(30); QCOMPARE(starts(), 1);
        QCOMPARE(password(*view)->property("text").toString(), QStringLiteral("synthetic-retained"));
    }
    void sessionRemovalAndRestorationRequireExplicitSelection() {
        start(); const auto selected = context();
        password(*view)->setProperty("text", "synthetic-old-target");
        QVERIFY(changeSessionFile(QFileInfo(selected.session.fileName()).fileName(), false));
        QVERIFY(!policy->valid()); QCOMPARE(policy->sessionIndex(), -1);
        QCOMPARE(password(*view)->property("text").toString(), QString());
        QTRY_COMPARE(context().flag, quint32(0)); const auto clear = context();
        password(*view)->setProperty("text", "synthetic-input"); submit();
        QTest::qWait(30); QCOMPARE(count(GreeterMessages::Login), 0); QCOMPARE(starts(), 1);
        acknowledge(clear, false); QTRY_VERIFY(proxy->authenticationUser().isEmpty());
        QVERIFY(changeSessionFile(QFileInfo(selected.session.fileName()).fileName(), true));
        const int restoredIndex = sessions->indexOfSession(selected.session.type(), selected.session.fileName());
        QVERIFY(restoredIndex >= 0);
        QTest::qWait(30); QVERIFY(!policy->valid());
        QCOMPARE(context().serial, clear.serial); QCOMPARE(starts(), 1);
        QVERIFY(policy->select(view.get(), selected.user, restoredIndex));
        QTRY_VERIFY(context().serial > clear.serial); const auto restored = context();
        QVERIFY(request(restored) != request(selected));
        QCOMPARE(restored.session.type(), selected.session.type());
        QCOMPARE(restored.session.fileName(), selected.session.fileName());
        acknowledge(restored); QTRY_COMPARE(starts(), 2);
    }
    void committedSessionReorderAndSurfaceRetirement_data() {
        QTest::addColumn<int>("retirement");
        QTest::newRow("hide") << 0;
        QTest::newRow("root-destroy") << 1;
        QTest::newRow("window-destroy") << 2;
    }
    void committedSessionReorderAndSurfaceRetirement() {
        QFETCH(int, retirement);
        start(); const auto selected = context();
        state(selected, FingerprintState::Matched, AuthenticationPhase::SessionAuthorized);
        QTRY_VERIFY(proxy->authenticationBusy());
        const int publications = count(GreeterMessages::SetAuthenticationContext);
        QVERIFY(changeSessionFile("000-before.desktop", true));
        QCOMPARE(policy->sessionIndex(), sessions->indexOfSession(selected.session.type(), selected.session.fileName()));
        QVERIFY(policy->valid());
        QTest::qWait(30); QCOMPARE(count(GreeterMessages::SetAuthenticationContext), publications);
        QCOMPARE(starts(), 1);
        if (retirement == 0) view->hide();
        else if (retirement == 1) view->setSource(QUrl());
        else view.reset();
        QTest::qWait(30);
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), publications);
        QCOMPARE(count(GreeterMessages::CancelAuthenticationMethod), 0);
        QCOMPARE(starts(), 1); QVERIFY(proxy->authenticationBusy());
        finish(selected, AuthenticationResult::Succeeded, AuthenticationMethod::Fingerprint);
        QTest::qWait(30); QCOMPARE(starts(), 1);
    }
    void committedSessionRemovalPreservesAuthorizedIdentity() {
        start(); const auto selected = context();
        state(selected, FingerprintState::Matched, AuthenticationPhase::SessionAuthorized);
        QTRY_VERIFY(proxy->authenticationBusy());
        password(*view)->setProperty("text", "synthetic-retained");
        const int publications = count(GreeterMessages::SetAuthenticationContext);
        const QString authorizedRequest = proxy->fingerprintRequestId();
        QVERIFY(changeSessionFile(QFileInfo(selected.session.fileName()).fileName(), false));
        QTest::qWait(30);
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), publications);
        QVERIFY(proxy->authenticationBusy());
        QCOMPARE(policy->user(), selected.user);
        QCOMPARE(policy->sessionIndex(), -1);
        QCOMPARE(password(*view)->property("text").toString(), QStringLiteral("synthetic-retained"));
        QVERIFY(!policy->select(view.get(), "bob", 0));
        policy->retry(view.get()); policy->cancel(view.get());
        QVERIFY(changeSessionFile(QFileInfo(selected.session.fileName()).fileName(), true));
        QTRY_VERIFY(policy->valid());
        QCOMPARE(policy->sessionIndex(), sessions->indexOfSession(selected.session.type(), selected.session.fileName()));
        QCOMPARE(proxy->authenticationSessionIndex(), policy->sessionIndex());
        QCOMPARE(proxy->fingerprintRequestId(), authorizedRequest);
        QCOMPARE(password(*view)->property("text").toString(), QStringLiteral("synthetic-retained"));
        QTest::qWait(30); QCOMPARE(starts(), 1);
        QCOMPARE(count(GreeterMessages::Login), 0);
        QCOMPARE(count(GreeterMessages::CancelAuthenticationMethod), 0);
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), publications);
        QSignalSpy finished(proxy.get(), &GreeterProxy::authenticationFinished);
        finish(selected, AuthenticationResult::Succeeded, AuthenticationMethod::Fingerprint);
        QTRY_COMPARE(finished.size(), 1);
        QCOMPARE(starts(), 1);
    }
    void committedProxySurvivesMissingSessionModel_data() {
        QTest::addColumn<bool>("destroy");
        QTest::newRow("detach") << false;
        QTest::newRow("destroy") << true;
    }
    void committedProxySurvivesMissingSessionModel() {
        QFETCH(bool, destroy);
        start(); const auto selected = context();
        state(selected, FingerprintState::Matched, AuthenticationPhase::SessionAuthorized);
        QTRY_VERIFY(proxy->authenticationBusy());
        const QString authorizedRequest = proxy->fingerprintRequestId();
        const int publications = count(GreeterMessages::SetAuthenticationContext);
        // This row isolates the proxy's model lifetime, not policy model replacement.
        policy->setControllerView(nullptr); view.reset(); policy.reset();
        if (destroy) sessions.reset();
        else proxy->setSessionModel(nullptr);
        QCOMPARE(proxy->authenticationSessionIndex(), -1);
        QVERIFY(proxy->authenticationBusy());
        QCOMPARE(proxy->authenticationUser(), selected.user);
        QCOMPARE(proxy->fingerprintRequestId(), authorizedRequest);
        if (destroy) sessions = std::make_unique<Sessions>();
        proxy->setSessionModel(sessions.get());
        QCOMPARE(proxy->authenticationSessionIndex(), sessions->indexOfSession(selected.session.type(), selected.session.fileName()));
        QTest::qWait(30);
        QCOMPARE(count(GreeterMessages::SetAuthenticationContext), publications);
        QCOMPARE(count(GreeterMessages::CancelAuthenticationMethod), 0);
        QCOMPARE(count(GreeterMessages::Login), 0); QCOMPARE(starts(), 1);
        QSignalSpy finished(proxy.get(), &GreeterProxy::authenticationFinished);
        finish(selected, AuthenticationResult::Succeeded, AuthenticationMethod::Fingerprint);
        QTRY_COMPARE(finished.size(), 1);
    }
    void committedClearRejectionRestoresSessionAfterModelChange_data() {
        QTest::addColumn<bool>("removeSelected");
        QTest::newRow("reorder") << false;
        QTest::newRow("remove-selected") << true;
    }
    void committedClearRejectionRestoresSessionAfterModelChange() {
        QFETCH(bool, removeSelected);
        start(); const auto selected = context();
        const auto other = sessions->sessionIdentity(1);
        password(*view)->setProperty("text", "synthetic-original");
        QVERIFY(policy->select(view.get(), selected.user, 1));
        QCOMPARE(password(*view)->property("text").toString(), QString());
        password(*view)->setProperty("text", "synthetic-other-target");
        QTRY_COMPARE(context().flag, quint32(0)); const auto clear = context();
        QVERIFY(removeSelected ? changeSessionFile(QFileInfo(selected.session.fileName()).fileName(), false)
                               : changeSessionFile("000-before.desktop", true));
        send([&](QDataStream &out) {
            out << quint32(DaemonMessages::AuthenticationContext) << clear.serial << quint32(0)
                << request(selected) << selected.user << selected.session << quint32(AuthenticationAvailability::Available)
                << quint32(AuthenticationPhase::SessionAuthorized) << QStringLiteral("session_committed");
        });
        QTRY_VERIFY(proxy->authenticationBusy());
        int selectedIndex = sessions->indexOfSession(selected.session.type(), selected.session.fileName());
        QTRY_COMPARE(policy->sessionIndex(), selectedIndex);
        QCOMPARE(view->rootObject()->property("currentSessionsIndex").toInt(), selectedIndex);
        QCOMPARE(proxy->fingerprintRequestId(), request(selected));
        const auto identity = proxy->authenticationSessionIdentity();
        QCOMPARE(identity.value("type").toInt(), int(selected.session.type()));
        QCOMPARE(identity.value("file").toString(), selected.session.fileName());
        QCOMPARE(password(*view)->property("text").toString(), QString());
        QVERIFY(!policy->select(view.get(), "bob", 0));
        if (removeSelected) {
            QVERIFY(!policy->valid());
            QVERIFY(changeSessionFile(QFileInfo(selected.session.fileName()).fileName(), true));
            selectedIndex = sessions->indexOfSession(selected.session.type(), selected.session.fileName());
            QTRY_VERIFY(policy->valid());
            QCOMPARE(policy->sessionIndex(), selectedIndex);
        }
        QVERIFY(sessions->sessionIdentity(selectedIndex) != other);
        policy->retry(view.get()); policy->cancel(view.get());
        QTest::qWait(30); QCOMPARE(starts(), 1);
        QCOMPARE(context().serial, clear.serial);
        QCOMPARE(count(GreeterMessages::CancelAuthenticationMethod), 0);
        QCOMPARE(count(GreeterMessages::Login), 0);
        QCOMPARE(proxy->fingerprintRequestId(), request(selected));
        QSignalSpy finished(proxy.get(), &GreeterProxy::authenticationFinished);
        finish(selected, AuthenticationResult::Succeeded, AuthenticationMethod::Fingerprint);
        QTRY_COMPARE(finished.size(), 1); QCOMPARE(starts(), 1);
    }
    void rapidABARejectsLateAcknowledgement() {
        start(); const auto a = context();
        QVERIFY(policy->select(view.get(), "bob", 0));
        QTRY_COMPARE(context().flag, quint32(0));
        const auto clear = context(); acknowledge(clear, false);
        QTRY_VERIFY(context().serial > clear.serial); const auto b = context();
        QVERIFY(policy->select(view.get(), "alice", 0));
        QTRY_COMPARE(context().flag, quint32(0));
        const auto clearB = context();
        acknowledge(b); state(a, FingerprintState::Matched, AuthenticationPhase::SessionAuthorized);
        QTest::qWait(20); QCOMPARE(starts(), 1); QVERIFY(!proxy->authenticationBusy());
        acknowledge(clearB, false); QTRY_VERIFY(context().serial > clearB.serial);
        const auto nextA = context();
        acknowledge(nextA); QTRY_COMPARE(starts(), 2);
        QCOMPARE(frames.last().serial, nextA.serial);
    }
    void synchronousABACannotReuseAcknowledgedRequest() {
        start(); const auto a = context();
        QVERIFY(policy->select(view.get(), "bob", 0));
        QVERIFY(policy->select(view.get(), "alice", 0));
        QTRY_COMPARE(context().flag, quint32(0)); const auto clear = context();
        acknowledge(a); QTest::qWait(30); QCOMPARE(starts(), 1);
        acknowledge(clear, false); QTRY_VERIFY(context().serial > clear.serial);
        const auto nextA = context(); QCOMPARE(nextA.user, QStringLiteral("alice"));
        QVERIFY(request(nextA) != request(a));
        acknowledge(nextA); QTRY_COMPARE(starts(), 2);
    }
    void realThemeUserCyclePublishesExactNameAndClearsPassword() {
        start();
        password(*view)->setProperty("text", "synthetic-old-target");
        QVERIFY(QMetaObject::invokeMethod(view->rootObject(), "usersCycleSelectNext"));
        QCOMPARE(policy->user(), QStringLiteral("bob"));
        QCOMPARE(password(*view)->property("text").toString(), QString());
        QTRY_COMPARE(context().flag, quint32(0)); const auto clear = context(); acknowledge(clear, false);
        QTRY_VERIFY(context().serial > clear.serial); QCOMPARE(context().user, QStringLiteral("bob"));
        acknowledge(context()); QTRY_COMPARE(starts(), 2);
        password(*view)->setProperty("text", "synthetic-input"); submit();
        QTRY_COMPARE(count(GreeterMessages::Login), 1);
        QCOMPARE(frames.last().user, QStringLiteral("bob"));
    }
    void controllerRootOrWindowLossClears_data() {
        QTest::addColumn<bool>("wholeWindow");
        QTest::newRow("root-only") << false;
        QTest::newRow("whole-window") << true;
    }
    void controllerRootOrWindowLossClears() {
        QFETCH(bool, wholeWindow);
        start();
        if (wholeWindow) view.reset();
        else view->setSource(QUrl());
        QTRY_COMPARE(context().flag, quint32(0));
        acknowledge(context(), false); QTest::qWait(20); QCOMPARE(starts(), 1);
    }
    void mirrorRootWindowTransferDoesNotClearController() {
        start();
        QQuickView mirror;
        load(mirror, proxy.get(), adapted, false);
        QQuickWindow destination;
        destination.resize(1024, 768);
        destination.show();
        QTRY_VERIFY(destination.isExposed());
        const auto originalContext = context();
        const int publications = count(GreeterMessages::SetAuthenticationContext);
        auto *root = mirror.rootObject();
        auto *originalParent = root->parentItem();
        root->setParentItem(destination.contentItem());
        const bool moved = root->window() == &destination && root->isVisible();
        QTest::qWait(100);
        const auto afterMove = context();
        const int afterPublications = count(GreeterMessages::SetAuthenticationContext);
        root->setParentItem(originalParent);
        QVERIFY(moved);
        QCOMPARE(afterMove.serial, originalContext.serial);
        QCOMPARE(afterPublications, publications);
        QCOMPARE(starts(), 1);
        QVERIFY(proxy->authenticationSubmissionAllowed());
    }
    void liveRootWindowLoss_data() {
        QTest::addColumn<bool>("committed");
        QTest::addColumn<bool>("detached");
        QTest::newRow("moving-precommit") << false << false;
        QTest::newRow("detached-precommit") << false << true;
        QTest::newRow("moving-authorized") << true << false;
        QTest::newRow("detached-authorized") << true << true;
    }
    void liveRootWindowLoss() {
        QFETCH(bool, committed);
        QFETCH(bool, detached);
        start();
        const auto originalContext = context();
        const int publications = count(GreeterMessages::SetAuthenticationContext);
        if (committed) {
            state(originalContext, FingerprintState::Matched, AuthenticationPhase::SessionAuthorized);
            QTRY_VERIFY(proxy->authenticationBusy());
        }
        QQuickWindow destination;
        destination.resize(1024, 768);
        destination.show();
        QTRY_VERIFY(destination.isExposed());
        QVERIFY(view->isExposed());
        auto *root = view->rootObject();
        auto *originalParent = root->parentItem();
        root->setParentItem(detached ? nullptr : destination.contentItem());
        const bool moved = root->window() == (detached ? nullptr : &destination) && root->isVisible();
        QTest::qWait(100);
        const auto afterMove = context();
        const int afterPublications = count(GreeterMessages::SetAuthenticationContext);
        const bool busy = proxy->authenticationBusy();
        root->setParentItem(originalParent);
        QVERIFY(moved);
        QCOMPARE(starts(), 1);
        if (committed) {
            QVERIFY(busy);
            QCOMPARE(afterMove.serial, originalContext.serial);
            QCOMPARE(afterMove.request, originalContext.request);
            QCOMPARE(afterPublications, publications);
        } else {
            QCOMPARE(afterMove.flag, quint32(0));
            QVERIFY(afterMove.serial > originalContext.serial);
            QCOMPARE(afterPublications, publications + 1);
            QVERIFY(!proxy->authenticationSubmissionAllowed());
            submit();
            QCOMPARE(count(GreeterMessages::Login), 0);
            acknowledge(afterMove, false);
            QTRY_VERIFY(context().serial > afterMove.serial);
            acknowledge(context());
        }
        QTest::qWait(30);
        QCOMPARE(starts(), 1);
    }
    void committedTargetCannotBeChanged() {
        start(); const auto f = context();
        state(f, FingerprintState::Matched, AuthenticationPhase::SessionAuthorized);
        QTRY_VERIFY(proxy->authenticationBusy());
        QVERIFY(!policy->select(view.get(), "bob", 1));
        QCOMPARE(policy->user(), QStringLiteral("alice"));
        view->rootObject()->setProperty("currentUsersIndex", 1);
        QCOMPARE(view->rootObject()->property("currentUsersIndex").toInt(), 0);
        password(*view)->setProperty("text", "synthetic-retained");
        view->hide(); QTest::qWait(30);
        QCOMPARE(context().serial, f.serial); QCOMPARE(starts(), 1);
        QCOMPARE(password(*view)->property("text").toString(), QStringLiteral("synthetic-retained"));
    }
    void committedClearRejectionRestoresSharedAndRenderedIdentity() {
        start(); const auto a = context();
        QVERIFY(policy->select(view.get(), "bob", 0));
        QTRY_COMPARE(context().flag, quint32(0)); const auto clear = context();
        send([&](QDataStream &out) {
            out << quint32(DaemonMessages::AuthenticationContext) << clear.serial << quint32(0)
                << request(a) << a.user << a.session << quint32(AuthenticationAvailability::Available)
                << quint32(AuthenticationPhase::SessionAuthorized) << QStringLiteral("session_committed");
        });
        QTRY_VERIFY(proxy->authenticationBusy());
        QTRY_COMPARE(policy->user(), QStringLiteral("alice"));
        QCOMPARE(view->rootObject()->property("currentUsersIndex").toInt(), 0);
        policy->retry(view.get()); policy->cancel(view.get());
        QTest::qWait(30); QCOMPARE(starts(), 1);
        QCOMPARE(count(GreeterMessages::CancelAuthenticationMethod), 0);
        finish(a, AuthenticationResult::Succeeded, AuthenticationMethod::Fingerprint);
        QTest::qWait(30); QCOMPARE(starts(), 1);
    }
    void stockApiWithoutExtensionsAndStockDaemon() {
        setup(false);
        password(*view)->setProperty("text", "synthetic-input"); submit();
        QTRY_COMPARE(count(GreeterMessages::Login), 1);
        QCOMPARE(starts(), 0);
        policy->setControllerView(nullptr); view.reset();
        StockProxy stock; QQuickView target;
        load(target, &stock, adapted, true, true, false);
        password(target)->setProperty("text", "synthetic-input");
        QVERIFY(QMetaObject::invokeMethod(password(target), "accepted"));
        QCOMPARE(stock.submissions, 1);
    }
    void unchangedSurfacePixelsAndGeometry_data() {
        QTest::addColumn<QString>("input");
        QTest::newRow("empty") << QString();
        QTest::newRow("masked-synthetic") << QStringLiteral("visual-fixture");
    }
    void unchangedSurfacePixelsAndGeometry() {
        QFETCH(QString, input);
        start();
        password(*view)->setProperty("text", input);
        password(*view)->setProperty("cursorVisible", false);
        const QRectF bounds(password(*view)->position(), password(*view)->size());
        QTest::qWait(100); const QImage after = view->grabWindow(); QVERIFY(!after.isNull());
        policy->setControllerView(nullptr); view->hide();
        QQuickView baseline; load(baseline, proxy.get(), original, false, true, false);
        password(baseline)->setProperty("text", input); password(baseline)->setProperty("cursorVisible", false);
        QTest::qWait(100); const QImage before = baseline.grabWindow();
        QCOMPARE(QRectF(password(baseline)->position(), password(baseline)->size()), bounds);
        QCOMPARE(before, after);
        const auto evidence = qEnvironmentVariable("THEME_CONTEXT_EVIDENCE"); QVERIFY(!evidence.isEmpty());
        const QString suffix = QString::fromLatin1(QTest::currentDataTag()) + ".png";
        QVERIFY(before.save(evidence + "/original-" + suffix));
        QVERIFY(after.save(evidence + "/adapted-" + suffix));
    }
};
QTEST_MAIN(ThemeAutoTest)
#include "ThemeAutoTest.moc"
