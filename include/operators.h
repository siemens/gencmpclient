/*!*********************************************************************************************************************
 * @file
 * @brief Operator replacements for FM Platform.
 *
 * @author wssn: Nils Weiss, IC MOL RA R&D CCS 5 1, Tel. +49 531 226 2458, nils.weiss@siemens.com
 * @author adem: Marcel Aderhold, IC MOL RA R&D CCS 5 2, Tel. 4256, marcel.aderhold@siemens.com
 * @author MB: Martin Barta, CT RDA DS EU CZ RA SW 3, Tel. +420 601 121 637, martin.barta@siemens.com
 *
 * @copyright (c) Siemens AG 2018 all rights reserved confidential
 **********************************************************************************************************************/

#ifndef OPERATORS_H
#define OPERATORS_H

// This is the only operator that is required by the coding standard for SIMIS Platforms
// and is not defined in the C++ standard, or <ciso646>, or <iso646.h>
#define is_eq   ==

// The following operators reserved keywords in the C++ standard
// They are here, so that this header file can also be used by C source files
#ifndef __cplusplus

// These are recommended in the coding standard for SIMIS Platforms
#define and     &&
#define not_eq  !=
#define or      ||

// The following are not mentioned in the coding standard for SIMIS Platforms
#define and_eq  &=
#define bitand  &
#define bitor   |
#define compl   ~
#define not     !
#define or_eq   |=
#define xor     ^
#define xor_eq  ^=

#endif // __cplusplus

#ifdef FM_V3_COMPATIBILITY

// The following operators are available in the operatoren.h from the FM-Platform V3.x they are neither required by
// the coding standard nor the style guide for the FM-Platform V4.x.

// Bitweise Operatoren
#define sh_right   >>
#define sh_left    <<

// Arithmetische Operatoren
#define mod        %

#endif // FM_V3_COMPATIBILITY

// ROTATE_LEFT rotates x left n bits
// MB: I disabled this: it's dangerous because of the possible double evaluation of the arguments. If you want this
// make, an inline function.
// #define ROTATE_LEFT(x, n) (((x) << (n)) bitor ((x) >> (32-(n))))

#endif // OPERATORS_H
