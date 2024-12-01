#ifndef ERROR_CODES_H
#define ERROR_CODES_H

// Success Code
#define ERR_SUCCESS 0

// General Errors
#define ERR_INVALID_COMMAND          1
#define ERR_STORAGE_SERVER_UNAVAILABLE 2
#define ERR_NAMING_SERVER_UNAVAILABLE 3
#define ERR_INVALID_COMMAND_FORMAT   4
#define ERR_INVALID_PATH             5
#define ERR_UNKNOWN_ERROR            6
#define ERR_INVALID_ARGUMENTS        7
#define ERR_UNKNOWN_MESSAGE          8
#define ERR_CONNECTION_FAILED        9

// File Errors
#define ERR_FILE_NOT_FOUND           100
#define ERR_PATH_ALREADY_EXISTS      101
#define ERR_FILE_IN_USE              102
#define ERR_FILE_CREATION_FAILED     103
#define ERR_FILE_DELETION_FAILED     104
#define ERR_FILE_READ_FAILED         105
#define ERR_FILE_WRITE_FAILED        106
#define ERR_FILE_COPY_FAILED         107

// Directory Errors
#define ERR_DIR_NOT_FOUND            200
#define ERR_DIR_ALREADY_EXISTS       201
#define ERR_DIR_CREATION_FAILED      202
#define ERR_DIR_DELETION_FAILED      203

// Permission Errors
#define ERR_PERMISSION_DENIED        300

// Other Errors
#define ERR_PATH_NOT_ALLOWED         400

#endif // ERROR_CODES_H