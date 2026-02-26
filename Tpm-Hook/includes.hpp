#pragma once

#include <ntifs.h>
#include <minwindef.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include <bcrypt.h>
#include <stddef.h>

#include "tpm20.h"
#include "tpm_structs.hpp"
#include "memory.hpp"
#include "spoofer.hpp"

#define DEBUG_LOG(x, ...) DbgPrintEx(0, 0, "[sys-core] " x "\n", __VA_ARGS__)