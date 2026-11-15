#ifndef QRCODELABEL_H
#define QRCODELABEL_H

#include "precompiled.h"

class QRCodeLabel : public QLabel
{
    Q_OBJECT
public:
    explicit        QRCodeLabel(QWidget *parent = nullptr);
    virtual QSize   sizeHint() const;
    
    void            setQrcodeString(QString address);
    QPixmap         scaledPixmap() const;
public slots:    
    void resizeEvent(QResizeEvent *);

private:
    QString          str;
    // Cached decoded QR module grid (row-major, qrSize*qrSize), so resizeEvent()
    // only re-scales/re-rasters instead of re-running the full encoder each tick.
    // qrSize <= 0 is the 'unset' sentinel (mirrors the !str.isEmpty() guard).
    QVector<bool>    qrModules;
    int              qrSize = 0;
};


#endif // QRCODELABEL_H
