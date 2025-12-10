cmake_minimum_required(VERSION 3.16)

project(sniffer_project VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Quick Widgets)

qt_standard_project_setup(REQUIRES 6.8)

qt_add_executable(appsniffer_project
    main.cpp
    src/core/CaptureManager.cpp
    src/core/CaptureWorker.cpp
    src/core/IpReassembler.cpp
    src/core/PacketParser.cpp

    src/core/Utils.cpp

    src/core/CaptureManager.h
    src/core/CaptureWorker.h
    src/core/IpReassembler.h
    src/core/PacketParser.h
    src/core/ProtocolHeaders.h
    src/core/Utils.h
    src/core/Packet.h

    src/ui/MainWindow.cpp
    src/ui/MainWindow.h
    src/ui/FilterDialog.cpp
    src/ui/FilterDialog.h
    src/ui/PacketDetailModel.cpp
    src/ui/PacketDetailModel.h
    src/ui/PacketTableModel.cpp
    src/ui/PacketTableModel.h

)

qt_add_qml_module(appsniffer_project
    URI sniffer_project
    QML_FILES
        Main.qml
)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
set_target_properties(appsniffer_project PROPERTIES
#    MACOSX_BUNDLE_GUI_IDENTIFIER com.example.appsniffer_project
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

target_link_libraries(appsniffer_project
    PRIVATE Qt6::Quick
            Qt6::Widgets
            pcap

)

include(GNUInstallDirs)
install(TARGETS appsniffer_project
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

