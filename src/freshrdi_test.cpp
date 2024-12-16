#include "freshrdi.hpp"
#include <al/gtest/pic.hpp>

struct FreshRDITest : public PICTest<FreshRDITest> {
    inline static std::string_view path = FRESHRDI_PIC_PATH;
    inline static unsigned long permissions = PAGE_EXECUTE_READWRITE;
    freshrdi_t m_pic = nullptr;
};

TEST_F(FreshRDITest, PositionIndependent) {
    EXPECT_EQ(error::SUCCESS, m_pic());
}