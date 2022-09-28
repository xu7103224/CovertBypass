#pragma once

#include "types.h"
#include "hook.h"

#include "bypass.h"

COVERT_API void be_cleanup();
COVERT_API bool be_initialize(PIMAGE_INFO image_info);