#include <QCoreApplication>
#include <QSslSocket>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <cstdio>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    if (!QSslSocket::supportsSsl()) {
        fputs("FAIL: Qt TLS support unavailable\n", stderr);
        return 1;
    }
    QNetworkAccessManager network;
    QNetworkRequest request(QUrl("https://api.github.com/repos/ZclassicCommunity/zclassic/releases?per_page=1"));
    request.setRawHeader("User-Agent", "ZClassicWalletReleaseCheck");
    QNetworkReply* reply = network.get(request);
    // Never ignore SSL errors. Certificate and hostname validation stay enabled.
    QObject::connect(reply, &QNetworkReply::finished, &app, [&]() {
        if (reply->error() != QNetworkReply::NoError ||
            reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 200) {
            fprintf(stderr, "TLS request failed: %s\n", qPrintable(reply->errorString()));
            app.exit(2);
            return;
        }
        puts("PASS: verified HTTPS request to canonical release endpoint");
        app.exit(0);
    });
    QTimer::singleShot(20000, &app, [&]() { app.exit(3); });
    return app.exec();
}
