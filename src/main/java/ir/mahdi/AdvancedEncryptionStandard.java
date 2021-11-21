package ir.mahdi;
// Mahdi Rezazadeh
// 974421020
// Urmia university

import lombok.Getter;


// Tests written ir/mahdi/AdvancedEncryptionStandardTest.java
@Getter
public class AdvancedEncryptionStandard {
    private String plainText;
    private String key;

    private int[][][] expandedKey = new int[11][4][4];

    private static final int[][] sBox = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

    private static final int[] rC = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

    private static final int[][] mixColumnFactor = {
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2}};

    public int[][] getMixColumnFactor() {
        return mixColumnFactor;
    }

    public AdvancedEncryptionStandard(String plainText, String key) {
        setPlainText(plainText);
        setKey(key);
    }


    public void setPlainText(String plainText) {
        plainText = fixLengthTo16(plainText.replaceAll(" ", ""));
        this.plainText = plainText;
    }

    public void setKey(String key) {
        key = fixLengthTo16(key.replaceAll(" ", ""));
        this.key = key;
    }


    /**
     * key expansion method
     *
     * @param matrix int[4][4] matrix, hex of characters of key
     */
    private void keyExpansion(int[][] matrix) {
        expandedKey[0] = matrix;
        for (int time = 1; time < 11; time++) {
            int[] g = g(expandedKey[time - 1], time - 1);
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    if (col == 0) {
                        expandedKey[time][row][col] = expandedKey[time - 1][row][col] ^ g[col];
                    } else {
                        expandedKey[time][row][col] = expandedKey[time - 1][row][col] ^ expandedKey[time][row][col - 1];
                    }
                }
            }
        }
    }

    /**
     * subBytes method
     *
     * @param matrix message
     * @return subBytes of message
     */
    public int[][] subBytes(int[][] matrix) {
        int[][] subBytes = new int[4][4];
        for (int row = 0; row < matrix.length; row++) {
            for (int col = 0; col < matrix[row].length; col++) {
                int sBoxRow = matrix[row][col] / 16;
                int sBoxCol = matrix[row][col] % 16;
                subBytes[row][col] = AdvancedEncryptionStandard.sBox[sBoxRow][sBoxCol];
            }
        }
        return subBytes;
    }

    /**
     * shiftRows method
     *
     * @param matrix subBytes of message
     * @return shifted rows message
     */
    public int[][] shiftRows(int[][] matrix) {
        int[][] shifted = new int[4][4];
        for (int row = 0; row < matrix.length; row++) {
            shifted[row] = shiftLeft(matrix[row], row);
        }
        return shifted;
    }

    /**
     * add Round key method
     *
     * @param message shifted rows message
     * @param round   round of encryption
     * @return encrypted message
     */
    public int[][] addRoundKey(int[][] message, int round) {
        int[][] result = new int[4][4];
        for (int row = 0; row < message.length; row++) {
            for (int col = 0; col < message[0].length; col++) {
                result[row][col] = message[row][col] ^ expandedKey[round + 1][row][col];
            }
        }
        return result;
    }

    /**
     * Mix Columns method
     *
     * @param message int[4][4] message
     * @return calculated mix column result
     */
    public int[][] mixColumns(int[][] message) {
        return multiplyMatricesXOR(mixColumnFactor, message);
    }

    private String fixLengthTo16(String key) {
        if (key.length() < 16) {
            StringBuilder plainTextBuilder = new StringBuilder(key);
            while (plainTextBuilder.length() < 16) {
                plainTextBuilder.append("z");
            }
            key = plainTextBuilder.toString();
        } else if (key.length() > 16) {
            key = key.substring(0, 16);
        }
        return key;
    }

    public int[] convertTextToHex(String text) {
        int[] hex = new int[16];
        char[] chars = text.toLowerCase().toCharArray();
        for (int index = 0; index < chars.length; index++) {
            hex[index] = chars[index] - 'a';
        }
        return hex;
    }

    public int[][] convertArrayToMatrix(int[] hex) {
        int[][] matrix = new int[4][4];
        for (int col = 0; col < matrix[0].length; col++) {
            for (int row = 0; row < matrix.length; row++) {
                matrix[row][col] = hex[(col * 4) + row];
            }
        }
        return matrix;
    }


    public int[] convertArrayBySBox(int[] array) {
        int[] subBytes = new int[array.length];
        for (int index = 0; index < array.length; index++) {
            int SBoxRow = array[index] / 16;
            int SBoxCol = array[index] % 16;
            subBytes[index] = AdvancedEncryptionStandard.sBox[SBoxRow][SBoxCol];
        }
        return subBytes;
    }


    private int[] shiftLeft(int[] row, int times) {
        int[] res = new int[row.length];
        System.arraycopy(row, times, res, 0, row.length - times);
        System.arraycopy(row, 0, res, row.length - times, times);
        return res;
    }

    public int[][] multiplyMatricesXOR(int[][] firstMatrix, int[][] secondMatrix) {
        int[][] result = new int[firstMatrix.length][secondMatrix[0].length];

        for (int row = 0; row < result.length; row++) {
            for (int col = 0; col < result[row].length; col++) {
                result[row][col] = multiplyMatricesCellXOR(firstMatrix, secondMatrix, row, col);
            }
        }

        return result;
    }

    public int multiplyMatricesCellXOR(int[][] firstMatrix, int[][] secondMatrix, int row, int col) {
        int cell = 0;
        for (int i = 0; i < secondMatrix.length; i++) {
            switch (firstMatrix[row][i]) {
                case 1 -> cell ^= secondMatrix[i][col];
                case 2 -> cell ^= cellMultiplyBy2(secondMatrix[i][col]);
                case 3 -> cell ^= cellMultiplyBy3(secondMatrix[i][col]);
            }
        }
        return cell;
    }

    private int cellMultiplyBy3(int secondMatrix) {
        int value = cellMultiplyBy2(secondMatrix) ^ secondMatrix;
        if (value / 256 > 0)
            value = value % 256;
        return value;
    }

    private int cellMultiplyBy2(int secondMatrix) {
        int value = 2 * secondMatrix;
        if (value / 256 > 0) {
            value = value ^ 27;
            if (value / 256 > 0)
                value = value % 256;
        }
        return value;
    }

    private int[] g(int[][] matrix, int j) {
        int[] row = new int[4];
        for (int index = 0; index < 4; index++) {
            row[index] = matrix[index][3];
        }
        row = shiftLeft(row, 1);
        row = convertArrayBySBox(row);
        row[0] = row[0] ^ rC[j];

        return row;
    }


}
