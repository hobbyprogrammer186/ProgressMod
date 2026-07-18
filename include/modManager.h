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

#ifndef PROGRESSMOD_MODMANAGER_H
#define PROGRESSMOD_MODMANAGER_H

#include <QString>

class ModManager {
public:
    ModManager();
    ~ModManager();
    void enable();
    void disable();
private:
    QString modName, modDescription, modVersion, modIdentifier;
    void setModProperty(const QString& name, const QString& desc, const QString& ver, const QString ident) {
        modName = name;
        modDescription = desc;
        modVersion = ver;
        modIdentifier = ident;
    }

    friend struct ModManagerBind;
};

#endif //PROGRESSMOD_MODMANAGER_H
