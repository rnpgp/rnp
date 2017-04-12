
#ifndef __RNP__CONSTANTS_H__
#define __RNP__CONSTANTS_H__

/* Copyright (c) 2017 Ribose Inc.
 * common/constants.h
 */

/* The dot directory relative to the user's home directory where keys
 * are stored.
 *
 * TODO: Consider making this an overridable config setting.
 *
 * TODO: For now the dot dot directory is .rnp to prevent competition with
 *       developers' .gnupg installations.
 */

#define SUBDIRECTORY_GNUPG ".rnp"
#define SUBDIRECTORY_SSH   ".ssh"

#endif
