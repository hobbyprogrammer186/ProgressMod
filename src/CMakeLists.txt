add_executable(ProgressMod
    main.cpp
    modManager.cpp
    engine.cpp
)
target_link_libraries(ProgressMod PRIVATE
    Qt::Core
    Qt::Gui
    Qt::Widgets
    Python3::Python
    pybind11::embed
)
if(TARGET capstone::capstone)
    target_link_libraries(ProgressMod PRIVATE capstone::capstone)
elseif(TARGET PkgConfig::CAPSTONE)
    target_link_libraries(ProgressMod PRIVATE PkgConfig::CAPSTONE)
endif()
if(TARGET ELF::libelf)
    target_link_libraries(ProgressMod PRIVATE ELF::libelf)
elseif(TARGET PkgConfig::ELF)
    target_link_libraries(ProgressMod PRIVATE PkgConfig::ELF)
endif()
