#include "openfhe.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lbcrypto;

constexpr std::size_t INPUT_H = 4;
constexpr std::size_t INPUT_W = 4;
constexpr std::size_t KERNEL_H = 3;
constexpr std::size_t KERNEL_W = 3;
constexpr std::size_t OUTPUT_H = 2;
constexpr std::size_t OUTPUT_W = 2;
constexpr std::size_t BATCH_SIZE = 16;

constexpr double ERROR_TOLERANCE = 1e-5;

using Input4x4 = std::array<double, INPUT_H * INPUT_W>;
using Kernel3x3 = std::array<double, KERNEL_H * KERNEL_W>;
using Output2x2 = std::array<double, OUTPUT_H * OUTPUT_W>;

struct OperationStats {
    std::size_t rotations = 0;
    std::size_t plaintextMultiplications = 0;
    std::size_t ciphertextAdditions = 0;
};

Output2x2 PlainConv2D(
    const Input4x4& input,
    const Kernel3x3& kernel) {

    Output2x2 output{};

    for (std::size_t outRow = 0; outRow < OUTPUT_H; ++outRow) {
        for (std::size_t outCol = 0; outCol < OUTPUT_W; ++outCol) {
            double sum = 0.0;

            for (std::size_t kernelRow = 0;
                 kernelRow < KERNEL_H;
                 ++kernelRow) {

                for (std::size_t kernelCol = 0;
                     kernelCol < KERNEL_W;
                     ++kernelCol) {

                    const std::size_t inputRow =
                        outRow + kernelRow;

                    const std::size_t inputCol =
                        outCol + kernelCol;

                    const std::size_t inputIndex =
                        inputRow * INPUT_W + inputCol;

                    const std::size_t kernelIndex =
                        kernelRow * KERNEL_W + kernelCol;

                    sum += input[inputIndex] * kernel[kernelIndex];
                }
            }

            output[outRow * OUTPUT_W + outCol] = sum;
        }
    }

    return output;
}

CryptoContext<DCRTPoly> CreateCKKSContext() {
    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);
    parameters.SetBatchSize(BATCH_SIZE);
    parameters.SetSecurityLevel(HEStd_128_classic);

    auto cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    return cryptoContext;
}

Ciphertext<DCRTPoly> CountedRotate(
    const CryptoContext<DCRTPoly>& cryptoContext,
    const Ciphertext<DCRTPoly>& ciphertext,
    int32_t offset,
    OperationStats& stats) {

    ++stats.rotations;
    return cryptoContext->EvalRotate(ciphertext, offset);
}

Ciphertext<DCRTPoly> CountedMultPlain(
    const CryptoContext<DCRTPoly>& cryptoContext,
    const Ciphertext<DCRTPoly>& ciphertext,
    const Plaintext& plaintext,
    OperationStats& stats) {

    ++stats.plaintextMultiplications;
    return cryptoContext->EvalMult(ciphertext, plaintext);
}

Ciphertext<DCRTPoly> CountedAdd(
    const CryptoContext<DCRTPoly>& cryptoContext,
    const Ciphertext<DCRTPoly>& lhs,
    const Ciphertext<DCRTPoly>& rhs,
    OperationStats& stats) {

    ++stats.ciphertextAdditions;
    return cryptoContext->EvalAdd(lhs, rhs);
}

std::vector<double> MakeWeightMask(
    double kernelValue,
    std::size_t supportShift) {

    static constexpr std::array<std::size_t, 4> outputSlots{
        0, 1, 4, 5
    };

    std::vector<double> mask(BATCH_SIZE, 0.0);

    for (const std::size_t outputSlot : outputSlots) {
        const std::size_t maskSlot =
            (outputSlot + supportShift) % BATCH_SIZE;

        mask[maskSlot] = kernelValue;
    }

    return mask;
}

Ciphertext<DCRTPoly> EncryptedConv2DDirect(
    const CryptoContext<DCRTPoly>& cryptoContext,
    const Ciphertext<DCRTPoly>& encryptedInput,
    const Kernel3x3& kernel,
    OperationStats& stats) {

    static constexpr std::array<int32_t, 9> offsets{
        0, 1, 2,
        4, 5, 6,
        8, 9, 10
    };

    Ciphertext<DCRTPoly> encryptedOutput;

    for (std::size_t i = 0; i < offsets.size(); ++i) {
        Ciphertext<DCRTPoly> shiftedInput;

        if (offsets[i] == 0) {
            shiftedInput = encryptedInput;
        } else {
            shiftedInput = CountedRotate(
                cryptoContext,
                encryptedInput,
                offsets[i],
                stats);
        }

        const auto weightMask =
            MakeWeightMask(kernel[i], 0);

        const Plaintext weightPlaintext =
            cryptoContext->MakeCKKSPackedPlaintext(
                weightMask);

        const auto contribution =
            CountedMultPlain(
                cryptoContext,
                shiftedInput,
                weightPlaintext,
                stats);

        if (i == 0) {
            encryptedOutput = contribution;
        } else {
            encryptedOutput = CountedAdd(
                cryptoContext,
                encryptedOutput,
                contribution,
                stats);
        }
    }

    return encryptedOutput;
}

Ciphertext<DCRTPoly> ComputeKernelRowBSGS(
    const CryptoContext<DCRTPoly>& cryptoContext,
    const std::array<Ciphertext<DCRTPoly>, KERNEL_W>& babyRotations,
    const Kernel3x3& kernel,
    std::size_t kernelRow,
    OperationStats& stats) {

    Ciphertext<DCRTPoly> rowSum;

    // OpenFHE 正索引为左旋。后续整体左旋 4*kernelRow，
    // 因此这里将明文掩码预先向右放置 4*kernelRow 个槽位。
    const std::size_t supportShift =
        kernelRow * INPUT_W;

    for (std::size_t kernelCol = 0;
         kernelCol < KERNEL_W;
         ++kernelCol) {

        const std::size_t kernelIndex =
            kernelRow * KERNEL_W + kernelCol;

        const auto weightMask =
            MakeWeightMask(
                kernel[kernelIndex],
                supportShift);

        const Plaintext weightPlaintext =
            cryptoContext->MakeCKKSPackedPlaintext(
                weightMask);

        const auto contribution =
            CountedMultPlain(
                cryptoContext,
                babyRotations[kernelCol],
                weightPlaintext,
                stats);

        if (kernelCol == 0) {
            rowSum = contribution;
        } else {
            rowSum = CountedAdd(
                cryptoContext,
                rowSum,
                contribution,
                stats);
        }
    }

    return rowSum;
}

Ciphertext<DCRTPoly> EncryptedConv2DBSGS(
    const CryptoContext<DCRTPoly>& cryptoContext,
    const Ciphertext<DCRTPoly>& encryptedInput,
    const Kernel3x3& kernel,
    OperationStats& stats) {

    // Baby steps: offsets 0, 1, 2.
    const std::array<Ciphertext<DCRTPoly>, KERNEL_W> babyRotations{
        encryptedInput,
        CountedRotate(
            cryptoContext,
            encryptedInput,
            1,
            stats),
        CountedRotate(
            cryptoContext,
            encryptedInput,
            2,
            stats)
    };

    std::array<Ciphertext<DCRTPoly>, KERNEL_H> rowSums;

    for (std::size_t kernelRow = 0;
         kernelRow < KERNEL_H;
         ++kernelRow) {

        rowSums[kernelRow] =
            ComputeKernelRowBSGS(
                cryptoContext,
                babyRotations,
                kernel,
                kernelRow,
                stats);
    }

    // Giant steps: offsets 0, 4, 8.
    const auto shiftedRow1 =
        CountedRotate(
            cryptoContext,
            rowSums[1],
            4,
            stats);

    const auto shiftedRow2 =
        CountedRotate(
            cryptoContext,
            rowSums[2],
            8,
            stats);

    auto encryptedOutput =
        CountedAdd(
            cryptoContext,
            rowSums[0],
            shiftedRow1,
            stats);

    encryptedOutput =
        CountedAdd(
            cryptoContext,
            encryptedOutput,
            shiftedRow2,
            stats);

    return encryptedOutput;
}

std::vector<double> DecryptSlots(
    const CryptoContext<DCRTPoly>& cryptoContext,
    const PrivateKey<DCRTPoly>& secretKey,
    const Ciphertext<DCRTPoly>& ciphertext) {

    Plaintext decryptedPlaintext;

    cryptoContext->Decrypt(
        secretKey,
        ciphertext,
        &decryptedPlaintext);

    if (!decryptedPlaintext) {
        throw std::runtime_error("CKKS decryption failed");
    }

    decryptedPlaintext->SetLength(BATCH_SIZE);

    return decryptedPlaintext->GetRealPackedValue();
}

Output2x2 ExtractOutput(
    const std::vector<double>& decodedSlots) {

    if (decodedSlots.size() < BATCH_SIZE) {
        throw std::runtime_error(
            "Decoded slot vector is shorter than expected");
    }

    return {
        decodedSlots[0],
        decodedSlots[1],
        decodedSlots[4],
        decodedSlots[5]
    };
}

double MaxAbsoluteError(
    const Output2x2& expected,
    const Output2x2& actual) {

    double maxError = 0.0;

    for (std::size_t i = 0; i < expected.size(); ++i) {
        maxError = std::max(
            maxError,
            std::abs(expected[i] - actual[i]));
    }

    return maxError;
}

std::size_t MinimumBSGSRotations(
    std::size_t requiredOffsets,
    std::size_t& optimalBabyStepSize) {

    std::size_t minimumRotations = requiredOffsets - 1;
    optimalBabyStepSize = 1;

    for (std::size_t babyStepSize = 1;
         babyStepSize <= requiredOffsets;
         ++babyStepSize) {

        const std::size_t giantStepGroups =
            (requiredOffsets + babyStepSize - 1) /
            babyStepSize;

        const std::size_t rotations =
            (babyStepSize - 1) +
            (giantStepGroups - 1);

        if (rotations < minimumRotations) {
            minimumRotations = rotations;
            optimalBabyStepSize = babyStepSize;
        }
    }

    return minimumRotations;
}

template <std::size_t Rows, std::size_t Cols>
void PrintMatrix(
    const std::string& title,
    const std::array<double, Rows * Cols>& matrix) {

    std::cout << title << " =\n";

    for (std::size_t row = 0; row < Rows; ++row) {
        std::cout << (row == 0 ? "  [ " : "    ");

        for (std::size_t col = 0; col < Cols; ++col) {
            std::cout
                << std::setw(12)
                << std::fixed
                << std::setprecision(6)
                << matrix[row * Cols + col];
        }

        std::cout
            << (row + 1 == Rows ? " ]\n\n" : "\n");
    }
}

void PrintSlots(
    const std::string& title,
    const std::vector<double>& slots) {

    std::cout << title << "\n";

    const std::size_t slotCount =
        std::min(slots.size(), BATCH_SIZE);

    for (std::size_t row = 0; row < INPUT_H; ++row) {
        std::cout << (row == 0 ? "  [ " : "    ");

        for (std::size_t col = 0; col < INPUT_W; ++col) {
            const std::size_t index =
                row * INPUT_W + col;

            const double value =
                index < slotCount &&
                std::abs(slots[index]) >= 5e-9
                    ? slots[index]
                    : 0.0;

            std::cout
                << std::setw(12)
                << std::fixed
                << std::setprecision(6)
                << value;
        }

        std::cout
            << (row + 1 == INPUT_H ? " ]\n\n" : "\n");
    }
}

void PrintStatsComparison(
    const OperationStats& direct,
    const OperationStats& bsgs) {

    std::cout
        << "  +--------------------------+------------+------------+\n"
        << "  | Operation                | Direct     | BSGS       |\n"
        << "  +--------------------------+------------+------------+\n"
        << "  | Rotations                | "
        << std::setw(10) << direct.rotations << " | "
        << std::setw(10) << bsgs.rotations << " |\n"
        << "  | Plain multiplications    | "
        << std::setw(10) << direct.plaintextMultiplications << " | "
        << std::setw(10) << bsgs.plaintextMultiplications << " |\n"
        << "  | Ciphertext additions     | "
        << std::setw(10) << direct.ciphertextAdditions << " | "
        << std::setw(10) << bsgs.ciphertextAdditions << " |\n"
        << "  +--------------------------+------------+------------+\n\n";
}

int main() {
    try {
        const Input4x4 input{
             1.1,  2.2,  3.3,  4.4,
             5.5,  6.6,  7.7,  8.8,
             9.9, 10.1, 11.2, 12.3,
            13.4, 14.5, 15.6, 16.7
        };

        const Kernel3x3 kernel{
             0.2, -0.3,  0.4,
             0.5,  0.6, -0.7,
             0.8, -0.9,  1.0
        };

        const Output2x2 expectedOutput =
            PlainConv2D(input, kernel);

        auto cryptoContext = CreateCKKSContext();

        const auto keyPair =
            cryptoContext->KeyGen();

        if (!keyPair.good()) {
            throw std::runtime_error(
                "OpenFHE key generation failed");
        }

        // 两种方案同时测试，因此生成所需旋转密钥的并集。
        const std::vector<int32_t> rotationIndices{
            1, 2, 4, 5, 6, 8, 9, 10
        };

        cryptoContext->EvalRotateKeyGen(
            keyPair.secretKey,
            rotationIndices);

        const std::vector<double> packedInput(
            input.begin(),
            input.end());

        const Plaintext inputPlaintext =
            cryptoContext->MakeCKKSPackedPlaintext(
                packedInput);

        const auto encryptedInput =
            cryptoContext->Encrypt(
                keyPair.publicKey,
                inputPlaintext);

        OperationStats directStats;
        OperationStats bsgsStats;

        const auto directCiphertext =
            EncryptedConv2DDirect(
                cryptoContext,
                encryptedInput,
                kernel,
                directStats);

        const auto bsgsCiphertext =
            EncryptedConv2DBSGS(
                cryptoContext,
                encryptedInput,
                kernel,
                bsgsStats);

        const auto directSlots =
            DecryptSlots(
                cryptoContext,
                keyPair.secretKey,
                directCiphertext);

        const auto bsgsSlots =
            DecryptSlots(
                cryptoContext,
                keyPair.secretKey,
                bsgsCiphertext);

        const Output2x2 directOutput =
            ExtractOutput(directSlots);

        const Output2x2 bsgsOutput =
            ExtractOutput(bsgsSlots);

        const double directError =
            MaxAbsoluteError(
                expectedOutput,
                directOutput);

        const double bsgsError =
            MaxAbsoluteError(
                expectedOutput,
                bsgsOutput);

        const double methodDifference =
            MaxAbsoluteError(
                directOutput,
                bsgsOutput);

        const std::size_t requiredOffsets =
            KERNEL_H * KERNEL_W;

        std::size_t optimalBabyStepSize = 0;

        const std::size_t theoreticalMinimum =
            MinimumBSGSRotations(
                requiredOffsets,
                optimalBabyStepSize);

        const bool directCorrect =
            directError < ERROR_TOLERANCE;

        const bool bsgsCorrect =
            bsgsError < ERROR_TOLERANCE;

        const bool methodsAgree =
            methodDifference < ERROR_TOLERANCE;

        const bool countsCorrect =
            directStats.rotations == 8 &&
            bsgsStats.rotations == theoreticalMinimum;

        const bool passed =
            directCorrect &&
            bsgsCorrect &&
            methodsAgree &&
            countsCorrect;

        std::cout
            << "\n"
            << "OpenFHE CKKS Encrypted Convolution\n"
            << "==================================\n\n"
            << "[1] Experiment configuration\n"
            << "  Scheme                 : CKKS\n"
            << "  Input shape            : 1 x 4 x 4\n"
            << "  Kernel shape           : 1 x 3 x 3\n"
            << "  Stride / padding       : 1 / 0\n"
            << "  Output shape           : 1 x 2 x 2\n"
            << "  Batch size             : "
            << BATCH_SIZE << '\n'
            << "  Ring dimension         : "
            << cryptoContext->GetRingDimension() << '\n'
            << "  Output slots           : 0, 1, 4, 5\n\n";

        std::cout
            << "[2] Input data\n\n";

        PrintMatrix<INPUT_H, INPUT_W>(
            "Input matrix (4 x 4)",
            input);

        PrintMatrix<KERNEL_H, KERNEL_W>(
            "Kernel matrix (3 x 3)",
            kernel);

        std::cout
            << "[3] Convolution results\n\n";

        PrintMatrix<OUTPUT_H, OUTPUT_W>(
            "Plaintext reference",
            expectedOutput);

        PrintMatrix<OUTPUT_H, OUTPUT_W>(
            "Direct FHE result",
            directOutput);

        PrintMatrix<OUTPUT_H, OUTPUT_W>(
            "BSGS FHE result",
            bsgsOutput);

        std::cout
            << "[4] Decrypted slot layouts\n\n";

        PrintSlots(
            "Direct decrypted slots",
            directSlots);

        PrintSlots(
            "BSGS decrypted slots",
            bsgsSlots);

        std::cout
            << "[5] Operation-count comparison\n\n";

        PrintStatsComparison(
            directStats,
            bsgsStats);

        std::cout
            << "  Direct rotation keys   : "
            << "{1, 2, 4, 5, 6, 8, 9, 10}\n"
            << "  BSGS rotation keys     : "
            << "{1, 2, 4, 8}\n\n"
            << "  BSGS cost formula      : "
            << "R(b) = (b - 1) + (ceil(9 / b) - 1)\n"
            << "  Optimal baby-step size : b = "
            << optimalBabyStepSize << '\n'
            << "  BSGS minimum rotations : R("
            << optimalBabyStepSize << ") = "
            << theoreticalMinimum << '\n'
            << "  Actual BSGS rotations  : "
            << bsgsStats.rotations << '\n'
            << "  Minimum reached        : "
            << (bsgsStats.rotations == theoreticalMinimum
                    ? "YES"
                    : "NO")
            << "\n\n";

        std::cout
            << "[6] Correctness verification\n"
            << std::scientific
            << std::setprecision(8)
            << "  Direct maximum error   : "
            << directError << '\n'
            << "  BSGS maximum error     : "
            << bsgsError << '\n'
            << "  Difference of methods  : "
            << methodDifference << '\n'
            << "  Error tolerance        : "
            << ERROR_TOLERANCE << '\n'
            << std::fixed
            << "  Rotation reduction     : "
            << directStats.rotations
            << " -> "
            << bsgsStats.rotations
            << " (50%)\n"
            << "  Verification           : "
            << (passed ? "PASS" : "FAIL")
            << '\n';

        return passed ? 0 : 1;

    } catch (const std::exception& error) {
        std::cerr
            << "Error: "
            << error.what()
            << '\n';

        return 1;
    }
}
