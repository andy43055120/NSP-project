Step 1. 建立 base image

docker build -t ec_base .

Step 2. 修改 Dockerfile（加入 exploit / triage等等，需要甚麼加甚麼）

FROM ec_base

COPY exploit /exploit
COPY triage /triage

RUN chmod +x /exploit /triage

Step 3. 建立 image

docker build -t my_ec .

Step 4. 測試

docker run -it --rm \
  -v $(pwd)/shared:/shared \
  my_ec


Step5. 最終會把grader.sh放到EC裡面跑 (1~4完全不跑自己改都可以 到時候能提供正確再現你的EC環境的流程就好)
