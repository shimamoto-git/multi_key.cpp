/*
 *build/CMakeList.txt内、
 *add_executableをadd_executable(multi_key_ckks multi_key_ckks.cpp)に変更
 *このとき導入したCMakeList.txt内ではコメントアウトされていることもあるので注意
 *build内でmakeすると、オブジェクトファイルmulti_key_ckksが生成される
 *./multi_key_ckksで実行可能
 */

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // CKKS用パラメータ設定
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2); // 積演算の深さ
    parameters.SetScalingModSize(50); // 精度（小数点）
    parameters.SetBatchSize(8); // ベクトル長
    parameters.SetSecurityLevel(HEStd_128_classic); // 「現代の標準的な安全性」セキュリティレベルを設定

    // 初期化
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE); // 公開鍵を有効化
    cc->Enable(KEYSWITCH); // 鍵の切り替えを有効化
    cc->Enable(LEVELEDSHE); // レベル付き準同型暗号を有効化
    cc->Enable(ADVANCEDSHE); // 高度な準同型演算機能を有効化
    cc->Enable(PRE); // プロキシ再暗号化を有効化
    cc->Enable(MULTIPARTY); // マルチパーティー計算を有効化

    std::cout << "CKKS CryptoContext generated." << std::endl;

    // ユーザーAの鍵生成
    auto kpA = cc->KeyGen(); // 公開鍵と秘密鍵を生成
    cc->EvalMultKeyGen(kpA.secretKey); // 生成した秘密鍵から乗算（EvalMult）に必要な鍵を生成
    cc->EvalSumKeyGen(kpA.secretKey); // ベクトルの和（EvalSum）を使うための鍵を生成
    
    // ユーザーBの鍵生成
    auto kpB = cc->KeyGen(); // 公開鍵と秘密鍵を生成
    cc->EvalMultKeyGen(kpB.secretKey); // 生成した秘密鍵から乗算（EvalMult）に必要な鍵を生成
    cc->EvalSumKeyGen(kpB.secretKey); // ベクトルの和（EvalSum）を使うための鍵を生成

    // 平文（小数）の作成
    std::vector<double> vecA = {0.5, 2.2, 3.3};
    std::vector<double> vecB = {4.4, 5.5, 6.6};

    // 平文をCKKSスキームで暗号化可能な平文オブジェクト Plaintext に変換
    Plaintext ptA = cc->MakeCKKSPackedPlaintext(vecA);
    Plaintext ptB = cc->MakeCKKSPackedPlaintext(vecB);

    // 暗号化
    auto ctA = cc->Encrypt(kpA.publicKey, ptA);
    auto ctB = cc->Encrypt(kpB.publicKey, ptB);

    // 再暗号化（ctBをkpA用に変換）
    auto reKey = cc->ReKeyGen(kpB.secretKey, kpA.publicKey);
    auto ctB_switched = cc->ReEncrypt(ctB, reKey);

    // 加算・乗算
    auto ctAdd = cc->EvalAdd(ctA, ctB_switched);
    auto ctMul = cc->EvalMult(ctA, ctB_switched);

    // 復号と出力
    Plaintext ptAddResult, ptMulResult;
    cc->Decrypt(kpA.secretKey, ctAdd, &ptAddResult);
    ptAddResult->SetLength(vecA.size());

    cc->Decrypt(kpA.secretKey, ctMul, &ptMulResult);
    ptMulResult->SetLength(vecA.size());

    std::cout << "Add result: " << ptAddResult << std::endl;
    std::cout << "Mul result: " << ptMulResult << std::endl;

    return 0;
}
