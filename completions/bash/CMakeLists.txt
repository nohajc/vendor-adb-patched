set(BASH_COMPLETION_DIR "${CMAKE_INSTALL_FULL_DATADIR}/bash-completion/completions")

configure_file(termux-adb.in termux-adb)
configure_file(termux-fastboot.in termux-fastboot)

install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/termux-adb"
	"${CMAKE_CURRENT_BINARY_DIR}/termux-fastboot"
	DESTINATION "${BASH_COMPLETION_DIR}")
