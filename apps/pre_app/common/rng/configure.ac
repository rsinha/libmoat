AC_INIT([drng_samples], [2.0], [John Mechalas <john.p.mechalas@intel.com>])

AC_PROG_CC

bins="testdrng"

AC_MSG_CHECKING([if $CC understands rdrand])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([], [asm volatile("rdrand %rdx");])],
	AC_MSG_RESULT([yes]) ;\
		AC_DEFINE(HAVE_RDRAND, [],
			[Define if your compiler understands the rdrand instruction]),
	AC_MSG_RESULT([no]) 
)

AC_MSG_CHECKING([if $CC understands rdseed])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([], [asm volatile("rdseed %rdx");])],
	AC_MSG_RESULT([yes]) ;\
		AC_DEFINE(HAVE_RDSEED, [],
			[Define if your compiler understands the rdseed instruction]),
	AC_MSG_RESULT([no])
)

AC_CHECK_HEADER([gcrypt.h],
	AC_CHECK_LIB(
		[gcrypt],
		[gcry_check_version], 
		bins="$bins seed_from_rdrand rdrand128",
		AC_MSG_NOTICE([libgcrypt not found]);
		AC_MSG_NOTICE([seed_from_rdrand and rdrand128 samples will not be built!]);
	),
	AC_MSG_NOTICE([seed_from_rdrand and rdrand128 samples will not be built!]),
	[]
)

AC_CONFIG_HEADERS([config.h])

AC_SUBST([TARGET_BINS], "$bins")
AC_OUTPUT([Makefile])

