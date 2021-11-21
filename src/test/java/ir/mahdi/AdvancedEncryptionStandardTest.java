package ir.mahdi;


import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

public class AdvancedEncryptionStandardTest {

    private static AdvancedEncryptionStandard aSE;
    private static final int[][] startOfRound = {
            {0xa4, 0x68, 0x6b, 0x02},
            {0x9c, 0x9f, 0x5b, 0x6a},
            {0x7f, 0x35, 0xea, 0x50},
            {0xf2, 0x2b, 0x43, 0x49},
    };

    private static final int[][] afterSubBytes = {
            {0x49, 0x45, 0x7f, 0x77},
            {0xde, 0xdb, 0x39, 0x02},
            {0xd2, 0x96, 0x87, 0x53},
            {0x89, 0xf1, 0x1a, 0x3b},
    };

    private static final int[][] afterShiftRows = {
            {0x49, 0x45, 0x7f, 0x77},
            {0xdb, 0x39, 0x02, 0xde},
            {0x87, 0x53, 0xd2, 0x96},
            {0x3b, 0x89, 0xf1, 0x1a},
    };

    private static final int[][] afterMixColumns = {
            {0x58, 0x1b, 0xdb, 0x1b},
            {0x4d, 0x4b, 0xe7, 0x6b},
            {0xca, 0x5a, 0xca, 0xb0},
            {0xf1, 0xac, 0xa8, 0xe5}
    };

    @BeforeAll
    public static void initASE() {
        aSE = new AdvancedEncryptionStandard("hello world from inside", "hello world from outside");
    }

    @Test
    public void subBytes() {
        int[][] subBytes = aSE.subBytes(startOfRound);
        for (int row = 0; row < subBytes.length; row++) {
            assertArrayEquals(afterSubBytes[row], subBytes[row]);
        }
    }

    @Test
    public void shiftRows() {
        int[][] shiftRows = aSE.shiftRows(afterSubBytes);
        for (int row = 0; row < shiftRows.length; row++) {
            assertArrayEquals(afterShiftRows[row], shiftRows[row]);
        }
    }

    @Test
    public void addRoundKey() {

    }

    @Test
    public void mixColumns() {
        int[][] mixColumns = aSE.mixColumns(afterShiftRows);
        for (int row = 0; row < mixColumns.length; row++) {
            assertArrayEquals(afterMixColumns[row], mixColumns[row]);
        }
    }

    @ParameterizedTest
    @CsvSource({
            "0, 0, 0x58",
            "1, 1, 0x4b",
            "2, 3, 0xb0",
            "0, 1, 0x1b",
            "3, 1, 0xac",})
    public void multiplyMatricesCellXOR(int row, int col, int expected) {
        AdvancedEncryptionStandard aES = new AdvancedEncryptionStandard("test", "test2");
        int res = aES.multiplyMatricesCellXOR(aES.getMixColumnFactor(), afterShiftRows, row, col);
        assertEquals(expected, res);
    }
}