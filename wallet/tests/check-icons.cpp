#include <QApplication>
#include <QIcon>
#include <QImage>
#include <QPixmap>

#include "fillediconlabel.h"

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    QIcon icon(QStringLiteral(":/icons/res/icon.png"));
    if (icon.isNull()) {
        qCritical("PNG application icon did not load from Qt resources");
        return 1;
    }
    const int sizes[] = {16, 24, 32, 48, 64, 128, 256};
    for (int size : sizes) {
        if (icon.pixmap(size, size).isNull()) {
            qCritical("PNG application icon is empty at %d px", size);
            return 2;
        }
    }

    FilledIconLabel label;
    label.setBasePixmap(icon.pixmap(64, 64));
    label.resize(64, 64);
    label.show();
    app.processEvents();
    const QPixmap rendered = label.pixmap(Qt::ReturnByValue);
    if (rendered.isNull()) {
        qCritical("scaled icon did not render");
        return 3;
    }
    if (rendered.toImage().pixelColor(0, 0).alpha() != 0) {
        qCritical("scaled icon has an opaque corner background");
        return 4;
    }

    puts("icons: PNG resources load at 16-256 px and scaled backgrounds stay transparent");
    return 0;
}
