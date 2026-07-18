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

#ifndef ENGINE_H
#define ENGINE_H

#include <QString>
#include <QStringList>
#include <variant>
#include <string>
#include <cstdint>

typedef enum {
    EXECUTION_BEFORE = 0,
    EXECUTION_AFTER  = 1,
} ExecutionTiming;

typedef struct {
    unsigned int startAddr;
    unsigned int endAddr;
    std::string permissions;
    std::string backing_file;
} DataRegion;

/*
 * getValueOfVariable Usage:
 * objectPath   - Path Of Variable For Example:
 *              - Root Variable: 'foo'
 *              - Variable Into Function: 'example/foo'
 */
extern std::variant<char*, int, double, short, long> getValueOfVariable(int pid, QString objectPath);

/*
 * setValueOfVariable Usage:
 * progressIds  - Progress Id Array
 * objectPath   - Path Of Variable For Example:
 *              - Root Variable: 'foo'
 *              - Variable Into Function: 'example/foo'
 */
extern void setValueOfVariable(int progressIds[], int progressIdsCount, QString objectPath, std::variant<char*, int, double, short, long> value);

/*
 * addFunctionCallback Usage:
 * progressIds  - Progress Id Array
 * destination  - Destination Path Of Variable For Example: 'square:1'
 */
extern int addFunctionCallback(int progressIds[], int progressIdsCount, QString destination, ExecutionTiming timing, void*(callback)());

/*
 * removeFunctionDefinitionOrCallback Usage:
 * progressIds  - Progress Id Array
 * source       - Source Path Of Variable For Example:
 *              - Removing Function Callback 'square:1'
 *              - Removing Function Definition 'square'
 */
extern void removeStatement(int progressIds[], int progressIdsCount, QString source);
extern QStringList listFunctions(int pid);

#endif // ENGINE_H