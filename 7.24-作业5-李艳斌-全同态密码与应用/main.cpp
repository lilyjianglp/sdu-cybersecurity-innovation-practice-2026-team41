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

                    const std::size_t inputRow = outRow + kernelRow;
                    const std::size_t inputCol = outCol + kernelCol;

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

std::vector<double> MakeWeightVector(double kernelValue) {
    std::vector<double> weights(BATCH_SIZE, 0.0);

    // 四个有效输出位置：y00、y01、y10、y11
    weights[0] = kernelValue;
    weights[1] = kernelValue;
    weights[4] = kernelValue;
    weights[5] = kernelValue;

    return weights;
}

Ciphertext<DCRTPoly> EncryptedConv2D(
    const CryptoContext<DCRTPoly>& cryptoContext,
    const Ciphertext<DCRTPoly>& encryptedInput,
    const Kernel3x3& kernel) {

    // 4×4 行优先布局中，3×3 卷积核对应的一维偏移
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
            // OpenFHE 中正索引表示向左旋转
            shiftedInput =
                cryptoContext->EvalRotate(encryptedInput, offsets[i]);
        }

        const auto weightVector = MakeWeightVector(kernel[i]);

        const Plaintext weightPlaintext =
            cryptoContext->MakeCKKSPackedPlaintext(weightVector);

        const auto contribution =
            cryptoContext->EvalMult(
                shiftedInput,
                weightPlaintext);

        if (i == 0) {
            encryptedOutput = contribution;
        } else {
            encryptedOutput =
                cryptoContext->EvalAdd(
                    encryptedOutput,
                    contribution);
        }
    }

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
        decodedSlots[0],  // y00
        decodedSlots[1],  // y01
        decodedSlots[4],  // y10
        decodedSlots[5]   // y11
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

template <std::size_t Rows, std::size_t Cols>
void PrintMatrix(
    const std::string& title,
    const std::array<double, Rows * Cols>& matrix) {

    std::cout << title << " =\n";

    for (std::size_t row = 0; row < Rows; ++row) {
        std::cout << (row == 0 ? "  [ " : "    ");
        for (std::size_t col = 0; col < Cols; ++col) {
            std::cout
                << std::setw(10)
                << std::fixed
                << std::setprecision(6)
                << matrix[row * Cols + col];
        }

        std::cout << (row + 1 == Rows ? " ]\n\n" : "\n");
    }
}

void PrintSlots(
    const std::string& title,
    const std::vector<double>& slots) {

    std::cout << title << "\n"
              << "Slot indices =\n";

    for (std::size_t row = 0; row < INPUT_H; ++row) {
        std::cout << (row == 0 ? "  [ " : "    ");
        for (std::size_t col = 0; col < INPUT_W; ++col) {
            const std::size_t index = row * INPUT_W + col;
            std::cout << std::setw(10) << index;
        }
        std::cout << (row + 1 == INPUT_H ? " ]\n\n" : "\n");
    }

    std::cout << "Decrypted slots =\n";

    const std::size_t slotCount = std::min(slots.size(), BATCH_SIZE);
    for (std::size_t row = 0; row < INPUT_H; ++row) {
        std::cout << (row == 0 ? "  [ " : "    ");
        for (std::size_t col = 0; col < INPUT_W; ++col) {
            const std::size_t index = row * INPUT_W + col;
            const double value =
                index < slotCount && std::abs(slots[index]) >= 5e-9
                    ? slots[index]
                    : 0.0;

            std::cout << std::setw(10)
                      << std::fixed
                      << std::setprecision(6)
                      << value;
        }
        std::cout << (row + 1 == INPUT_H ? " ]\n\n" : "\n");
    }
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

        const auto keyPair = cryptoContext->KeyGen();

        if (!keyPair.good()) {
            throw std::runtime_error(
                "OpenFHE key generation failed");
        }

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

        const auto encryptedOutput =
            EncryptedConv2D(
                cryptoContext,
                encryptedInput,
                kernel);

        const auto decodedSlots =
            DecryptSlots(
                cryptoContext,
                keyPair.secretKey,
                encryptedOutput);

        const Output2x2 actualOutput =
            ExtractOutput(decodedSlots);

        const double maxError =
            MaxAbsoluteError(
                expectedOutput,
                actualOutput);

        const bool passed =
            maxError < ERROR_TOLERANCE;

        std::cout
            << "\n"
            << "OpenFHE CKKS Encrypted Convolution\n"
            << "==================================\n\n"
            << "[1] Experiment configuration\n";

        std::cout
            << "  Scheme             : CKKS\n"
            << "  Input shape        : 1 x 4 x 4\n"
            << "  Kernel shape       : 1 x 3 x 3\n"
            << "  Stride / padding   : 1 / 0\n"
            << "  Output shape       : 1 x 2 x 2\n"
            << "  Batch size         : " << BATCH_SIZE << '\n'
            << "  Ring dimension     : "
            << cryptoContext->GetRingDimension() << '\n'
            << "  Output slots       : 0, 1, 4, 5\n\n"
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
            "Decrypted FHE result",
            actualOutput);

        PrintSlots(
            "[4] Packed-slot layout",
            decodedSlots);

        std::cout
            << "[5] Correctness verification\n"
            << "  Maximum absolute error : "
            << std::scientific
            << std::setprecision(8)
            << maxError
            << '\n';

        std::cout
            << "  Error tolerance        : "
            << ERROR_TOLERANCE
            << "\n";

        std::cout
            << "  Verification           : "
            << (passed ? "PASS" : "FAIL")
            << "\n";

        return passed ? 0 : 1;

    } catch (const std::exception& error) {
        std::cerr
            << "Error: "
            << error.what()
            << '\n';

        return 1;
    }
}
