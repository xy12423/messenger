#pragma once

#ifndef _H_GLOB
#define _H_GLOB

static const uint8_t pac_type_msg = 0x00;
static const uint8_t pac_type_file_h = 0x01;
static const uint8_t pac_type_file_b = 0x02;

void ltrim(std::string &str);
void rtrim(std::string &str);
void trim(std::string &str);

#endif
