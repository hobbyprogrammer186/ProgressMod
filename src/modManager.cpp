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

#include <pybind11/embed.h>
#include <pybind11/stl.h>
#include <QString>
#include <modManager.h>

ModManager::ModManager() = default;
ModManager::~ModManager() = default;

namespace py = pybind11;

// Define the helper structure that has friend status in ModManager
struct ModManagerBind {
    static void setModProperty(ModManager& self, const char *name, const char *desc, const char *ver, const char *iden) {
        // Friend access allows us to call the private method directly
        self.setModProperty(
            QString::fromStdString(name),
            QString::fromStdString(desc),
            QString::fromStdString(ver),
            QString::fromStdString(iden)
        );
    }
};

PYBIND11_EMBEDDED_MODULE(modEngine, m) {
    // Bind the ModManager class type
    py::class_<ModManager>(m, "ModManager")
        // Bind the function as a method of ModManager using the friend helper
        .def("setModProperty", [](ModManager& self, const char *name, const char *description,
            const char *version, const char *identifier) {
            ModManagerBind::setModProperty(self, name, description, version, identifier);
        });
}