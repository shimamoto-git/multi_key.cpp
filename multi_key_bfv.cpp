/*
 *build/CMakeList.txt内、
 *add_executableをadd_executable(multi_key_bfv multi_key_bfv.cpp)に変更
 *このとき導入したCMakeList.txt内ではコメントアウトされていることもあるので注意
 *build内でmakeすると、オブジェクトファイルmulti_key_bfvが生成される
 *./multi_key_bfvで実行可能
 */

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // BFV用パラメータ設定
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537); // 104857601でも可能なことを確認済み
    parameters.SetMultiplicativeDepth(2); // 暗号文で何回乗算が可能か（今回は2回、a*b*cなど）
    parameters.SetSecurityLevel(HEStd_128_classic); // 「現代の標準的な安全性」セキュリティレベルを設定

    // 初期化
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE); // 公開鍵を有効化
    cc->Enable(KEYSWITCH); // 鍵の切り替えを有効化
    cc->Enable(LEVELEDSHE); // レベル付き準同型暗号を有効化
    cc->Enable(ADVANCEDSHE); // 高度な準同型演算機能を有効化
    cc->Enable(PRE); // プロキシ再暗号化を有効化
    cc->Enable(MULTIPARTY); // マルチパーティー計算を有効化

    std::cout << "CryptoContext generated." << std::endl;

    // ユーザーAの鍵生成
    auto kpA = cc->KeyGen(); // 公開鍵と秘密鍵を生成
    cc->EvalMultKeyGen(kpA.secretKey); // 生成した秘密鍵から乗算（EvalMult）に必要な鍵を生成
    cc->EvalSumKeyGen(kpA.secretKey); // ベクトルの和（EvalSum）を使うための鍵を生成
    
    // ユーザーBの鍵生成
    auto kpB = cc->KeyGen(); // 公開鍵と秘密鍵を生成
    cc->EvalMultKeyGen(kpB.secretKey); // 生成した秘密鍵から乗算（EvalMult）に必要な鍵を生成
    cc->EvalSumKeyGen(kpB.secretKey); // ベクトルの和（EvalSum）を使うための鍵を生成

    // 平文の作成
    Plaintext ptA = cc->MakePackedPlaintext({1, 2, 3});
    Plaintext ptB = cc->MakePackedPlaintext({4, 0, 6});

    // 暗号化
    auto ctA = cc->Encrypt(kpA.publicKey, ptA);
    auto ctB = cc->Encrypt(kpB.publicKey, ptB);

    // 鍵スイッチング（ユーザーBのデータをユーザーAで復号できるように）
    auto reKey = cc->ReKeyGen(kpB.secretKey, kpA.publicKey);
    auto ctB_switched = cc->ReEncrypt(ctB, reKey);

    // 加算と乗算
    auto ctAdd = cc->EvalAdd(ctA, ctB_switched);
    auto ctMul = cc->EvalMult(ctA, ctB_switched);

    // 復号（ユーザーAの秘密鍵で）
    Plaintext ptAddResult;
    cc->Decrypt(kpA.secretKey, ctAdd, &ptAddResult);
    ptAddResult->SetLength(3);

    Plaintext ptMulResult;
    cc->Decrypt(kpA.secretKey, ctMul, &ptMulResult);
    ptMulResult->SetLength(3);

    std::cout << "Add result: " << ptAddResult << std::endl;
    std::cout << "Mul result: " << ptMulResult << std::endl;

    return 0;
}
