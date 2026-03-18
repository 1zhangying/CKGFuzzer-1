#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "TIFF::tiff" for configuration ""
set_property(TARGET TIFF::tiff APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(TIFF::tiff PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libtiff.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS TIFF::tiff )
list(APPEND _IMPORT_CHECK_FILES_FOR_TIFF::tiff "${_IMPORT_PREFIX}/lib/libtiff.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
