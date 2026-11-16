#include "logger.h"

Logger::Logger(QObject *parent, QString fileName) : QObject(parent) {
    if (!fileName.isEmpty()) {
        if (!QDir().mkpath(QFileInfo(fileName).absolutePath())) {
            qWarning() << "Cannot create wallet log directory";
            return;
        }
        file = new QFile(fileName, this);
        if (!file->open(QIODevice::Append | QIODevice::Text)) {
            qWarning() << "Cannot open wallet log:" << file->errorString();
            return;
        }
    }
    
    write("=========Startup==========");
}

void Logger::write(const QString &value) {
    if (!file || !file->isOpen())
        return;
        
    QString text = value;
    text = QDateTime::currentDateTime().toString("dd.MM.yyyy hh:mm:ss ") + text;
    QTextStream out(file);
    out.setCodec("UTF-8");
    out << text << Qt::endl;
}

Logger::~Logger() {
    if (file != 0)
        file->close();
}
