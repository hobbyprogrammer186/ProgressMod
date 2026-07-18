// Copyright (C) 2026 First Person
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <QApplication>
#include <QWidget>
#include <QGuiApplication>
#include <QScreen>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QHBoxLayout>
#include <QPushButton>
#include <QSettings>
#include <QTreeWidget>
#include <QHeaderView>
#include <QStyledItemDelegate>
#include <QPainter>
#include <definitions.h>

class ModItemDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override {
        painter->save();

        QRect r = option.rect;
        bool selected = option.state & QStyle::State_Selected;

        if (selected) {
            painter->fillRect(r, option.palette.highlight());
            painter->setPen(option.palette.highlightedText().color());
        } else {
            painter->setPen(option.palette.text().color());
        }

        int iconSize = 32;
        int margin = 8;
        QRect iconRect(r.left() + margin, r.top() + margin, iconSize, iconSize);
        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        if (!icon.isNull()) {
            icon.paint(painter, iconRect);
        }

        int textX = iconRect.right() + margin;
        int textWidth = r.right() - textX - margin;

        QFont titleFont = option.font;
        titleFont.setPointSize(10);
        titleFont.setBold(true);
        painter->setFont(titleFont);
        QString title = index.data(Qt::DisplayRole).toString();
        QRect titleRect(textX, r.top() + 4, textWidth, 18);
        painter->drawText(titleRect, Qt::AlignLeft | Qt::AlignVCenter,
                          painter->fontMetrics().elidedText(title, Qt::ElideRight, textWidth));

        QFont subFont = option.font;
        subFont.setPointSize(8);
        painter->setFont(subFont);
        if (!selected) {
            painter->setPen(QColor(0x88, 0x88, 0x88));
        }
        QString subtitle = index.data(Qt::UserRole).toString();
        QRect subRect(textX, r.top() + 22, textWidth, 14);
        painter->drawText(subRect, Qt::AlignLeft | Qt::AlignVCenter,
                          painter->fontMetrics().elidedText(subtitle, Qt::ElideRight, textWidth));

        painter->restore();
    }

    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override {
        Q_UNUSED(option);
        Q_UNUSED(index);
        return QSize(200, 48);
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QSettings settings("", "ProgressMod");

    QWidget window;
    window.setWindowFlags(Qt::Popup | Qt::WindowStaysOnTopHint);

    QScreen *primaryScreen = QGuiApplication::primaryScreen();
    QRect availableGeo = primaryScreen->availableGeometry();

    window.setGeometry(availableGeo.right() - DEFAULT_WIDTH + 1,
                       availableGeo.top(),
                       DEFAULT_WIDTH,
                       availableGeo.height());

    QVBoxLayout parent;
    parent.setContentsMargins(15, 15, 15, 15);
    parent.setSpacing(10);

    auto *titleBar = new QHBoxLayout();
    auto *title = new QLabel(APP_NAME, &window);
    QFont titleFont = title->font();
    titleFont.setPointSize(18);
    titleFont.setBold(true);
    title->setFont(titleFont);
    title->setAlignment(Qt::AlignLeft);

    auto *BTNAddRemove = new QPushButton("Add");

    auto *BTNEnableDisable = new QPushButton("Disable");
    BTNEnableDisable->setEnabled(false);

    titleBar->addWidget(title);
    titleBar->addStretch();
    titleBar->addWidget(BTNEnableDisable);
    titleBar->addWidget(BTNAddRemove);

    QTreeWidget *listView = new QTreeWidget(&window);
    listView->setColumnCount(1);
    listView->header()->hide();
    listView->setRootIsDecorated(false);
    listView->setAnimated(true);
    listView->setItemDelegate(new ModItemDelegate(listView));

    QPixmap folderPixmap(32, 32);
    folderPixmap.fill(Qt::transparent);
    {
        QPainter p(&folderPixmap);
        p.setRenderHint(QPainter::Antialiasing);
        p.setBrush(QColor("#FFC107"));
        p.setPen(Qt::NoPen);
        p.drawRoundedRect(3, 9, 26, 18, 2, 2);
        p.drawRoundedRect(3, 5, 10, 5, 2, 2);
        p.setBrush(QColor("#FFB300"));
        p.drawRoundedRect(4, 10, 24, 16, 2, 2);
    }
    QIcon folderIcon(folderPixmap);

    for (int i = 1; i <= 5; ++i) {
        auto *item = new QTreeWidgetItem(listView);
        item->setIcon(0, folderIcon);
        item->setText(0, QString("Mod Name %1").arg(i));
        item->setData(0, Qt::UserRole, QString("Description or status of mod %1").arg(i));
    }

    for (auto mod : settings.value("mods", DEFAULT_WIDTH).toList()) {

    }

    listView->resizeColumnToContents(0);

    parent.addLayout(titleBar);
    parent.addWidget(listView, 1);

    window.setLayout(&parent);
    window.show();
    return app.exec();
}
