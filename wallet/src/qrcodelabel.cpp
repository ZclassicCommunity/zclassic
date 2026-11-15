#include "qrcodelabel.h"

QRCodeLabel::QRCodeLabel(QWidget *parent) :
    QLabel(parent)
{
    this->setMinimumSize(100, 100);
    setScaledContents(false);
}

QSize QRCodeLabel::sizeHint() const
{
    int w = this->width();
    return QSize(w, w);   // 1:1 
}

void QRCodeLabel::resizeEvent(QResizeEvent*)
{
    if(!str.isEmpty())
        QLabel::setPixmap(scaledPixmap());
}

QPixmap QRCodeLabel::scaledPixmap() const {
    QPixmap pm(size());
    pm.fill(Qt::white);

    // Re-raster from the cached module grid; the QR is encoded ONCE in
    // setQrcodeString(), not re-encoded on every resize tick (UITB-2).
    const int s = qrSize > 0 ? qrSize : 1;
    if(qrModules.size() < s*s)
        return pm;   // cache not populated yet; nothing to draw

    QPainter painter(&pm);
    const double w      = pm.width();
    const double h      = pm.height();
    const double aspect = w/h;
    const double size   = ((aspect>1.0)?h:w);
    const double scale  = size/(s+2);
    const double woff   = (w - size) > 0 ? (w - size) / 2 : 0;
    const double hoff   = (h - size) > 0 ? (h - size) / 2 : 0;

    // NOTE: For performance reasons my implementation only draws the foreground parts
    painter.setPen(Qt::NoPen);
    painter.setBrush(QColor(Qt::black));
    for(int y=0; y<s; y++) {
        for(int x=0; x<s; x++) {
            if(qrModules.at(y*s + x)) {  // true = black module
                const double rx1=(x+1)*scale + woff, ry1=(y+1)*scale + hoff;
                QRectF r(rx1, ry1, scale, scale);
                painter.drawRects(&r,1);
            }
        }
    }

    return pm;
}

void QRCodeLabel::setQrcodeString(QString stra) {
    str = stra;

    // Encode ONCE here (Reed-Solomon ECC + module raster) and cache the grid,
    // so resizeEvent()/scaledPixmap() only re-scale on window resize (UITB-2).
    qrModules.clear();
    qrSize = 0;
    if(!str.isEmpty()) {
        // MEDIUM error-correction (15%): scans far more reliably off a screen photo than
        // LOW, and keeps the longer zclassic:?amt=&memo= payment-request payload scannable.
        qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(str.toUtf8().constData(), qrcodegen::QrCode::Ecc::MEDIUM);
        qrSize = qr.getSize() > 0 ? qr.getSize() : 0;
        if(qrSize > 0) {
            qrModules.resize(qrSize * qrSize);
            for(int y = 0; y < qrSize; y++)
                for(int x = 0; x < qrSize; x++)
                    qrModules[y*qrSize + x] = qr.getModule(x, y);
        }
    }

    QLabel::setPixmap(scaledPixmap());
}