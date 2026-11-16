#include <QCoreApplication>
#include <QTemporaryDir>
#include <QProcess>
#include <QTcpServer>
#include <QFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QTimer>
#include <cstdio>
#include "../src/startupaccess.h"
#ifdef Q_OS_WIN
#include <windows.h>
#endif

// Real node/RPC startup, isolated from wallets, mainnet peers and canonical data.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    if (app.arguments().size() < 2 || app.arguments().size() > 3) return 2;
    QTemporaryDir data;
    QTcpServer reservation;
    if (!data.isValid() || !reservation.listen(QHostAddress::LocalHost, 0)) return 3;
    const auto port = reservation.serverPort();
    reservation.close();
    const QString cookiePath = data.filePath("rpc.cookie");
    // Avoid the legacy daemon's first-run shared-password config generator.
    // The GUI also creates a server-only configuration and uses cookie auth.
    QFile config(data.filePath("zclassic.conf"));
    if (!config.open(QIODevice::WriteOnly) || config.write("server=1\n") != 9) return 3;
    config.close();
#ifdef Q_OS_WIN
    if (app.arguments().contains("--repair-fixture")) {
        // Reproduce the upgrade failure using only this disposable regtest tree.
        HANDLE token = nullptr;
        union { TOKEN_USER user; BYTE bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]; } identity;
        DWORD size = 0;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 6;
        const bool identified = GetTokenInformation(token, TokenUser, &identity, sizeof(identity), &size);
        CloseHandle(token);
        if (!identified) return 6;
        alignas(DWORD) BYTE buffer[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE];
        auto acl = reinterpret_cast<PACL>(buffer);
        SECURITY_DESCRIPTOR descriptor;
        if (!InitializeAcl(acl, sizeof(buffer), ACL_REVISION) ||
            !AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, identity.user.User.Sid) ||
            !InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
            !SetFileSecurityW(reinterpret_cast<LPCWSTR>(data.path().utf16()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &descriptor)) return 6;
        if (!InitializeAcl(acl, sizeof(buffer), ACL_REVISION) ||
            !SetFileSecurityW(reinterpret_cast<LPCWSTR>(config.fileName().utf16()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &descriptor)) return 6;
        const auto repaired = checkStartupAccess({data.path()}, true);
        if (!repaired.error.isEmpty() || repaired.repaired != 2) {
            fputs("FAIL: isolated access repair\n", stderr);
            return 6;
        }
    }
#endif
    QProcess node;
#ifdef Q_OS_WIN
    node.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* args) {
        args->flags |= CREATE_NO_WINDOW;
    });
#endif
    node.setStandardOutputFile(QProcess::nullDevice());
    node.setStandardErrorFile(data.filePath("stderr.txt"));
    node.start(app.arguments().at(1), {"-regtest", "-server=1", "-disablewallet=1",
        "-listen=0", "-connect=0", "-bootstrap=0", "-dnsseed=0", "-discover=0",
        "-datadir=" + data.path(), "-rpccookiefile=" + cookiePath,
        "-rpcport=" + QString::number(port)});
    if (!node.waitForStarted(10000)) return 4;
    QNetworkAccessManager network;
    auto request = [&](const QByteArray& method) {
        QFile cookie(cookiePath);
        if (!cookie.open(QIODevice::ReadOnly)) return QJsonObject();
        const QByteArray auth = cookie.readLine().trimmed();
        if (auth.isEmpty()) return QJsonObject();
        QNetworkRequest req(QUrl("http://127.0.0.1:" + QString::number(port)));
        req.setRawHeader("Authorization", "Basic " + auth.toBase64());
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        auto* reply = network.post(req, "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"" + method + "\",\"params\":[]}");
        QEventLoop loop;
        QTimer timer;
        timer.setSingleShot(true);
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        timer.start(3000);
        loop.exec();
        QJsonObject response;
        if (reply->isFinished()) response = QJsonDocument::fromJson(reply->readAll()).object();
        else reply->abort();
        delete reply;
        return response;
    };
    QElapsedTimer deadline;
    deadline.start();
    bool connected = false;
    while (deadline.elapsed() < 90000 && node.state() != QProcess::NotRunning) {
        const auto response = request("getblockchaininfo");
        if (response.value("error").isNull() &&
            response.value("result").toObject().value("chain").toString() == "regtest") {
            connected = true;
            break;
        }
        QEventLoop pause;
        QTimer::singleShot(200, &pause, &QEventLoop::quit);
        pause.exec();
    }
    if (connected) request("stop");
    const bool stopped = node.waitForFinished(15000);
    if (!stopped) { node.kill(); node.waitForFinished(5000); }
    if (!connected || !stopped || node.exitCode() != 0) {
        fputs("FAIL: isolated node did not complete RPC startup and clean shutdown\n", stderr);
        QFile diagnostics(data.filePath("stderr.txt"));
        if (diagnostics.open(QIODevice::ReadOnly)) {
            const auto tail = diagnostics.readAll().right(4096);
            fwrite(tail.constData(), 1, size_t(tail.size()), stderr);
        }
        return 5;
    }
    puts("PASS: real isolated node startup, cookie-authenticated regtest RPC and clean shutdown");
    return 0;
}
