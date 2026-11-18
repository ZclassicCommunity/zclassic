#include <QGuiApplication>
#include <QScreen>
#include <cstdio>

// Release gate: construct QGuiApplication with the DEFAULT platform plugin from
// the bundle's own platforms\ directory. Creates no window and shows nothing;
// prints "platform=windows screens=N" or fails if the plugin cannot initialise.
int main(int argc, char** argv) {
    QGuiApplication app(argc, argv);
    printf("platform=%s screens=%d\n", qPrintable(QGuiApplication::platformName()),
           int(QGuiApplication::screens().size()));
    return 0;
}
