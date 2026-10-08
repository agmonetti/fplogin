/*
 * Copyright (c) 2026 fplogin contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import QtQuick 2.15
import QtQuick.Window 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    id: root
    width: 960
    height: 640
    color: "#101820"
    Accessible.role: Accessible.Pane

    readonly property bool controller: authenticationController
    property bool viewReady: false
    property bool contextPending: false
    property bool autoStartIssued: false
    property bool passwordSubmissionPending: false
    property string selectedUser: ""
    property string selectedSessionFile: ""
    property var selectedSessionType: undefined
    property string statusText: "Choose a user and session to begin."
    property string loginMessage: ""

    function userAt(index) {
        return index >= 0 && index < userModel.count ? String(userBox.valueAt(index) || "") : ""
    }
    function validUser(index) { return userAt(index).length > 0 }
    function sessionFileAt(index) {
        return index >= 0 && index < sessionModel.count ? String(sessionBox.valueAt(index) || "") : ""
    }
    function sessionTypeAt(index) {
        return index >= 0 && index < sessionModel.count ? sessionTypeLookup.valueAt(index) : undefined
    }
    function validSession(index) { return sessionFileAt(index).length > 0 && sessionTypeAt(index) !== undefined }
    function contextMatches() {
        return selectedUser.length > 0 && validSession(sessionBox.currentIndex) &&
               sddm.authenticationUser === selectedUser &&
               sddm.authenticationSessionIndex === sessionBox.currentIndex
    }

    function synchronizeContext() {
        if (!controller || !viewReady || sddm.authenticationBusy)
            return
        var user = userAt(userBox.currentIndex)
        var file = sessionFileAt(sessionBox.currentIndex)
        var type = sessionTypeAt(sessionBox.currentIndex)
        if (user === selectedUser && file === selectedSessionFile && type === selectedSessionType) {
            maybeStartFingerprint()
            return
        }
        selectedUser = user
        selectedSessionFile = file
        selectedSessionType = type
        autoStartIssued = false
        passwordSubmissionPending = false
        passwordField.clear()
        loginMessage = ""
        contextPending = false
        if (!selectedUser.length || !selectedSessionFile.length || selectedSessionType === undefined) {
            sddm.clearAuthenticationContext()
            statusText = "Select a valid user and desktop session. Fingerprint sign-in is unavailable."
            return
        }
        if (sddm.authenticationMethodsAvailable) {
            contextPending = true
            sddm.setAuthenticationContext(selectedUser, sessionBox.currentIndex)
        }
        maybeStartFingerprint()
    }

    function maybeStartFingerprint() {
        if (!controller || !viewReady)
            return
        if (!sddm.authenticationMethodsAvailable) {
            contextPending = false
        } else if (contextPending && contextMatches() && sddm.fingerprintRequestId.length) {
            contextPending = false
        } else if (!contextPending && !sddm.fingerprintRequestId.length &&
                   selectedUser.length && validSession(sessionBox.currentIndex) &&
                   sddm.authenticationSubmissionAllowed) {
            contextPending = true
            sddm.setAuthenticationContext(selectedUser, sessionBox.currentIndex)
        }
        if (contextPending || autoStartIssued)
            return
        if (!sddm.authenticationMethodsAvailable) {
            statusText = fingerprintDescription()
            return
        }
        if (!contextMatches() || !sddm.fingerprintRequestId.length || sddm.authenticationBusy)
            return
        if (sddm.fingerprintAvailable) {
            autoStartIssued = true
            statusText = "Starting fingerprint sign-in for " + selectedUser + ". You can type your password at any time."
            sddm.startFingerprint(selectedUser, sessionBox.currentIndex)
        } else {
            statusText = fingerprintDescription()
        }
    }

    function fingerprintDescription() {
        if (sddm.fingerprintDetailCode === "daemon_upgrade_required")
            return "This daemon requires the paired greeter upgrade. Sign-in is disabled for this incompatible protocol."
        if (!sddm.authenticationMethodsAvailable)
            return "Fingerprint sign-in is not supported. Password sign-in is available."
        if (!contextMatches())
            return "Preparing the selected account and session. Password sign-in is available."
        if (!sddm.fingerprintAvailable) {
            if (sddm.fingerprintDetailCode === "checking")
                return "Checking fingerprint availability. Password sign-in is available."
            if (sddm.fingerprintDetailCode === "no_device" || sddm.fingerprintDetailCode === "no_enrolled_finger")
                return "No usable fingerprint reader or enrolled print is available. Password sign-in is available."
            return "Fingerprint sign-in is unavailable. Password sign-in is available."
        }
        switch (sddm.fingerprintState) {
        case "ready": return "Fingerprint sign-in is ready. Touch the reader, or enter your password."
        case "scanning": return "Fingerprint authentication is in progress. You can type your password at any time."
        case "retry": return "Try again on the reader, or use your password."
        case "matched": return "Fingerprint recognized; completing sign-in."
        case "failed": return "Fingerprint sign-in failed. Retry, or use your password."
        case "cancelled": return "Fingerprint sign-in was cancelled. Retry, or use your password."
        case "timed_out": return "Fingerprint sign-in timed out. Retry, or use your password."
        case "unavailable": return "Fingerprint sign-in is unavailable. Password sign-in is available."
        default: return "Fingerprint status is being checked. Password sign-in is available."
        }
    }
    function mirrorStatus() {
        switch (sddm.fingerprintState) {
        case "ready": return "Fingerprint sign-in ready."
        case "scanning": return "Fingerprint authentication in progress."
        case "retry": return "Retry on the reader, or use the password."
        case "matched": return "Fingerprint recognized; completing sign-in."
        case "failed": return "Fingerprint sign-in failed."
        case "cancelled": return "Fingerprint sign-in cancelled."
        case "timed_out": return "Fingerprint sign-in timed out."
        case "unavailable": return "Fingerprint sign-in unavailable."
        default: return "Password sign-in is available."
        }
    }
    function fingerprintActive() {
        return sddm.fingerprintState === "ready" || sddm.fingerprintState === "scanning" || sddm.fingerprintState === "retry"
    }
    function fingerprintCancelable() {
        return fingerprintActive() || (autoStartIssued &&
               sddm.fingerprintState !== "failed" &&
               sddm.fingerprintState !== "cancelled" &&
               sddm.fingerprintState !== "timed_out" &&
               sddm.fingerprintState !== "matched" &&
               sddm.fingerprintState !== "unavailable")
    }
    function cancelFingerprintOnly() {
        if (controller && fingerprintCancelable())
            sddm.cancelFingerprint()
    }
    function submitPassword() {
        if (!controller || passwordSubmissionPending || !selectedUser.length ||
                !validSession(sessionBox.currentIndex) || !sddm.authenticationSubmissionAllowed)
            return
        passwordSubmissionPending = true
        loginMessage = "Signing in."
        sddm.login(selectedUser, passwordField.text, sessionBox.currentIndex)
    }
    function findSession() {
        for (var i = 0; i < sessionModel.count; ++i) {
            if (sessionFileAt(i) === selectedSessionFile && sessionTypeAt(i) === selectedSessionType)
                return i
        }
        return -1
    }
    function firstPowerControl() {
        if (powerButton.visible) return powerButton
        if (rebootButton.visible) return rebootButton
        if (hybridButton.visible) return hybridButton
        if (suspendButton.visible) return suspendButton
        if (hibernateButton.visible) return hibernateButton
        return userBox
    }
    function lastControlBeforePower() {
        return fingerprintButton.visible ? fingerprintButton : loginButton
    }
    function lastPowerControl() {
        if (hibernateButton.visible) return hibernateButton
        if (suspendButton.visible) return suspendButton
        if (hybridButton.visible) return hybridButton
        if (rebootButton.visible) return rebootButton
        if (powerButton.visible) return powerButton
        return lastControlBeforePower()
    }
    function nextPowerControl(button) {
        if (button === powerButton && rebootButton.visible) return rebootButton
        if ((button === powerButton || button === rebootButton) && hybridButton.visible) return hybridButton
        if ((button === powerButton || button === rebootButton || button === hybridButton) && suspendButton.visible) return suspendButton
        if ((button === powerButton || button === rebootButton || button === hybridButton || button === suspendButton) && hibernateButton.visible) return hibernateButton
        return userBox
    }
    function previousPowerControl(button) {
        if (button === hibernateButton && suspendButton.visible) return suspendButton
        if ((button === hibernateButton || button === suspendButton) && hybridButton.visible) return hybridButton
        if ((button === hibernateButton || button === suspendButton || button === hybridButton) && rebootButton.visible) return rebootButton
        if ((button === hibernateButton || button === suspendButton || button === hybridButton || button === rebootButton) && powerButton.visible) return powerButton
        return lastControlBeforePower()
    }

    function initializeSelection() {
        var initialUserIndex = -1
        var remembered = sddm.authenticationBusy ? sddm.authenticationUser : userModel.lastUser
        for (var i = 0; i < userModel.count; ++i) {
            if (userAt(i) === remembered) {
                initialUserIndex = i
                break
            }
        }
        if (!sddm.authenticationBusy && initialUserIndex < 0 && validUser(userModel.lastIndex))
            initialUserIndex = userModel.lastIndex
        if (!sddm.authenticationBusy && initialUserIndex < 0) {
            for (var j = 0; j < userModel.count; ++j) {
                if (validUser(j)) {
                    initialUserIndex = j
                    break
                }
            }
        }
        userBox.currentIndex = initialUserIndex
        var sessionIndex = sddm.authenticationBusy ? sddm.authenticationSessionIndex : sessionModel.lastIndex
        sessionBox.currentIndex = validSession(sessionIndex) ? sessionIndex :
                                  (sddm.authenticationBusy ? -1 : (validSession(0) ? 0 : -1))
        if (sddm.authenticationBusy) {
            if (selectedUser !== sddm.authenticationUser ||
                    selectedSessionFile !== sessionFileAt(sessionBox.currentIndex) ||
                    selectedSessionType !== sessionTypeAt(sessionBox.currentIndex)) {
                passwordField.clear()
                passwordSubmissionPending = false
            }
            selectedUser = sddm.authenticationUser
            selectedSessionFile = sessionFileAt(sessionBox.currentIndex)
            selectedSessionType = sessionTypeAt(sessionBox.currentIndex)
            contextPending = false
            statusText = fingerprintDescription()
        } else {
            synchronizeContext()
        }
        if (selectedUser.length && validSession(sessionBox.currentIndex))
            passwordField.forceActiveFocus()
        else if (userBox.count > 0)
            userBox.forceActiveFocus()
        else if (sessionBox.count > 0)
            sessionBox.forceActiveFocus()
    }

    function keepFocusVisible() {
        if (!viewReady || !controller)
            return
        Qt.callLater(function() {
            var window = root.Window.window
            var item = window ? window.activeFocusItem : null
            var flick = scroll.contentItem
            if (!item || !flick || !flick.contentItem)
                return
            while (item.parent && !item.objectName.length && item.parent !== flick.contentItem)
                item = item.parent
            var point = item.mapToItem(flick.contentItem, 0, 0)
            var maximum = Math.max(0, flick.contentHeight - flick.height)
            if (point.y < flick.contentY)
                flick.contentY = Math.max(0, point.y - 8)
            else if (point.y + item.height > flick.contentY + flick.height)
                flick.contentY = Math.min(maximum, point.y + item.height - flick.height + 8)
        })
    }

    onWidthChanged: keepFocusVisible()
    onHeightChanged: keepFocusVisible()
    Connections {
        target: root.Window.window
        function onActiveFocusItemChanged() { root.keepFocusVisible() }
    }

    onControllerChanged: {
        if (controller && viewReady)
            initializeSelection()
    }


    Connections {
        target: sddm
        function onAuthenticationUserChanged() { root.maybeStartFingerprint() }
        function onAuthenticationSessionIndexChanged() { root.maybeStartFingerprint() }
        function onFingerprintRequestIdChanged() { root.maybeStartFingerprint() }
        function onAuthenticationBusyChanged() {
            if (root.controller && sddm.authenticationBusy && !root.contextMatches())
                root.initializeSelection()
        }
        function onAuthenticationMethodsAvailableChanged() { root.maybeStartFingerprint() }
        function onFingerprintAvailableChanged() { root.maybeStartFingerprint() }
        function onFingerprintStateChanged() {
            if (root.controller && !root.contextPending && root.contextMatches())
                root.statusText = root.fingerprintDescription()
        }
        function onFingerprintDetailCodeChanged() {
            if (root.controller && !root.contextPending)
                root.statusText = root.fingerprintDescription()
        }
        function onLoginFailed() {
            if (!root.controller || !root.passwordSubmissionPending)
                return
            root.passwordSubmissionPending = false
            passwordField.clear()
            root.loginMessage = "Sign-in failed. Check your password and try again."
        }
        function onLoginSucceeded() {
            root.passwordSubmissionPending = false
            root.loginMessage = "Sign-in successful."
        }
        function onAuthenticationFinished(requestId, user, sessionIndex, result, winningMethod) {
            if (!root.controller || user !== root.selectedUser ||
                    sessionIndex !== sessionBox.currentIndex ||
                    requestId !== sddm.fingerprintRequestId)
                return
            if (result === 0 && winningMethod === 0 && root.passwordSubmissionPending) {
                passwordField.clear()
                root.loginMessage = "Sign-in failed. Check your password and try again."
            } else if (result === 0) {
                root.loginMessage = "Sign-in could not be completed. Retry, or use your password."
            }
            // A fingerprint/account result is not a failed password submission.
            // The proxy's aggregate loginFailed follows this correlated result.
            root.passwordSubmissionPending = false
        }

    }
    Connections {
        target: sessionModel
        function onModelReset() {
            if (!root.controller || !root.viewReady)
                return
            // ComboBox updates its rows during reset; inspect the new model afterwards.
            Qt.callLater(function() {
                sessionBox.currentIndex = root.findSession()
                if (!sddm.authenticationBusy)
                    root.synchronizeContext()
            })
        }
    }

    Keys.priority: Keys.BeforeItem
    Keys.onEscapePressed: function(event) {
        cancelFingerprintOnly()
        event.accepted = true
    }

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#172a3a" }
            GradientStop { position: 1.0; color: "#0b1118" }
        }
    }

    ScrollView {
        id: scroll
        anchors.fill: parent
        anchors.margins: Math.max(16, Math.min(root.width, root.height) * 0.04)
        clip: true
        contentWidth: availableWidth

    ColumnLayout {
        width: scroll.availableWidth
        height: Math.max(implicitHeight, scroll.availableHeight)
        spacing: 20
        Item { Layout.fillHeight: true }

        Rectangle {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: Math.min(scroll.availableWidth, 520)
            Layout.preferredHeight: card.implicitHeight + 56
            radius: 18
            color: "#f21c2933"
            border.color: "#607080"
            border.width: 1

            ColumnLayout {
                id: card
                anchors.fill: parent
                anchors.margins: 28
                spacing: 14

                Label {
                    text: sddm.hostName.length ? "Sign in to " + sddm.hostName : "Sign in"
                    color: "#ffffff"
                    font.pixelSize: 26
                    font.bold: true
                    Layout.fillWidth: true
                    Accessible.name: text
                }
                Label {
                    text: root.controller
                          ? (sddm.authenticationBusy ? "Completing sign-in for " + sddm.authenticationUser + "."
                                                     : "Choose your account and desktop session.")
                          : "Selected account: " + (sddm.authenticationUser.length ? sddm.authenticationUser : "none") +
                            " · " + (sddm.authenticationSessionIndex >= 0 && sddm.authenticationSessionIndex < sessionModel.count
                                    ? sessionBox.textAt(sddm.authenticationSessionIndex) + " · " : "") +
                            root.mirrorStatus()
                    color: "#d7e2eb"
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
                ComboBox {
                    id: userBox
                    objectName: "userSelector"
                    visible: root.controller
                    enabled: visible && !sddm.authenticationBusy
                    Layout.fillWidth: true
                    model: userModel
                    textRole: "name"
                    valueRole: "name"
                    Accessible.name: "User account"
                    KeyNavigation.tab: sessionBox
                    KeyNavigation.backtab: root.lastPowerControl()
                    onActivated: root.synchronizeContext()
                    delegate: ItemDelegate {
                        width: userBox.width
                        text: model.realName && model.realName.length ? model.realName + " (" + model.name + ")" : model.name
                        highlighted: userBox.highlightedIndex === index
                        Accessible.name: text
                    }
                }
                ComboBox {
                    id: sessionBox
                    objectName: "sessionSelector"
                    visible: root.controller
                    enabled: visible && !sddm.authenticationBusy
                    Layout.fillWidth: true
                    model: sessionModel
                    textRole: "name"
                    valueRole: "file"
                    Accessible.name: "Desktop session"
                    KeyNavigation.tab: passwordField
                    KeyNavigation.backtab: userBox
                    onActivated: root.synchronizeContext()
                    delegate: ItemDelegate {
                        width: sessionBox.width
                        text: model.name
                        highlighted: sessionBox.highlightedIndex === index
                        Accessible.name: model.name
                    }
                }
                ComboBox {
                    id: sessionTypeLookup
                    visible: false
                    enabled: false
                    model: sessionModel
                    valueRole: "type"
                }
                Label {
                    text: "Password"
                    color: "#ffffff"
                    font.pixelSize: 15
                    visible: root.controller
                    Layout.fillWidth: true
                }
                TextField {
                    id: passwordField
                    objectName: "passwordField"
                    visible: root.controller
                    enabled: visible && !sddm.authenticationBusy
                    Layout.fillWidth: true
                    placeholderText: "Password"
                    echoMode: TextInput.Password
                    selectByMouse: true
                    Accessible.name: "Password"
                    KeyNavigation.tab: loginButton
                    KeyNavigation.backtab: sessionBox
                    Keys.onReturnPressed: root.submitPassword()
                    Keys.onEnterPressed: root.submitPassword()
                    background: Rectangle {
                        color: "#101820"
                        radius: 6
                        border.width: passwordField.activeFocus ? 3 : 1
                        border.color: passwordField.activeFocus ? "#73c8ff" : "#82909c"
                    }
                }
                Label {
                    text: root.loginMessage
                    visible: root.controller && text.length > 0
                    color: "#ffe08a"
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    Accessible.name: text
                }
                Label {
                    text: root.statusText
                    visible: root.controller
                    color: (sddm.fingerprintState === "failed" || sddm.fingerprintState === "unavailable") ? "#ffd18a" : "#d7e2eb"
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    Accessible.name: "Fingerprint status: " + text
                }
                RowLayout {
                    visible: root.controller
                    Layout.fillWidth: true
                    spacing: 10
                    Button {
                        id: loginButton
                        objectName: "loginButton"
                        text: root.passwordSubmissionPending ? "Signing in…" : "Sign in with password"
                        enabled: root.controller && sddm.authenticationSubmissionAllowed && !root.passwordSubmissionPending && root.selectedUser.length > 0 && root.validSession(sessionBox.currentIndex)
                        Layout.fillWidth: true
                        Accessible.name: "Sign in with password"
                        KeyNavigation.tab: fingerprintButton.visible ? fingerprintButton : root.firstPowerControl()
                        KeyNavigation.backtab: passwordField
                        onClicked: root.submitPassword()
                    }
                    Button {
                        id: fingerprintButton
                        objectName: "fingerprintButton"
                        text: root.fingerprintCancelable() ? "Cancel fingerprint" : "Retry fingerprint"
                        visible: root.controller && sddm.authenticationMethodsAvailable && root.selectedUser.length > 0 && root.validSession(sessionBox.currentIndex)
                        enabled: visible && !sddm.authenticationBusy && !root.contextPending &&
                                 (root.fingerprintCancelable() || !root.autoStartIssued ||
                                  sddm.fingerprintState === "failed" ||
                                  sddm.fingerprintState === "cancelled" ||
                                  sddm.fingerprintState === "timed_out" ||
                                  sddm.fingerprintState === "unavailable")
                        Accessible.name: text
                        KeyNavigation.tab: root.firstPowerControl()
                        KeyNavigation.backtab: loginButton
                        onClicked: {
                            if (root.fingerprintCancelable())
                                root.cancelFingerprintOnly()
                            else {
                                root.autoStartIssued = true
                                sddm.startFingerprint(root.selectedUser, sessionBox.currentIndex)
                            }
                            passwordField.forceActiveFocus()
                        }
                    }
                }
            }
        }

        GridLayout {
            Layout.alignment: Qt.AlignHCenter
            Layout.maximumWidth: scroll.availableWidth
            columns: Math.max(1, Math.min(5, Math.floor(scroll.availableWidth / 150)))
            columnSpacing: 10
            rowSpacing: 10
            Button {
                id: powerButton
                objectName: "powerOffButton"
                text: "Shut down"
                visible: root.controller && sddm.canPowerOff
                Accessible.name: "Shut down"
                KeyNavigation.tab: root.nextPowerControl(powerButton)
                KeyNavigation.backtab: root.previousPowerControl(powerButton)
                onClicked: sddm.powerOff()
            }
            Button {
                id: rebootButton
                objectName: "rebootButton"
                text: "Restart"
                visible: root.controller && sddm.canReboot
                Accessible.name: "Restart"
                KeyNavigation.tab: root.nextPowerControl(rebootButton)
                KeyNavigation.backtab: root.previousPowerControl(rebootButton)
                onClicked: sddm.reboot()
            }
            Button {
                id: hybridButton
                objectName: "hybridSleepButton"
                text: "Hybrid sleep"
                visible: root.controller && sddm.canHybridSleep
                Accessible.name: "Hybrid sleep"
                KeyNavigation.tab: root.nextPowerControl(hybridButton)
                KeyNavigation.backtab: root.previousPowerControl(hybridButton)
                onClicked: sddm.hybridSleep()
            }
            Button {
                id: suspendButton
                objectName: "suspendButton"
                text: "Suspend"
                visible: root.controller && sddm.canSuspend
                Accessible.name: "Suspend"
                KeyNavigation.tab: root.nextPowerControl(suspendButton)
                KeyNavigation.backtab: root.previousPowerControl(suspendButton)
                onClicked: sddm.suspend()
            }
            Button {
                id: hibernateButton
                objectName: "hibernateButton"
                text: "Hibernate"
                visible: root.controller && sddm.canHibernate
                Accessible.name: "Hibernate"
                KeyNavigation.tab: root.nextPowerControl(hibernateButton)
                KeyNavigation.backtab: root.previousPowerControl(hibernateButton)
                onClicked: sddm.hibernate()
            }
        }
        Item { Layout.fillHeight: true }
    }
    }

    Component.onCompleted: {
        viewReady = true
        if (controller)
            initializeSelection()
    }
}
