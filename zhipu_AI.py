from zhipuai import ZhipuAI

client = ZhipuAI(api_key="aefb1b0854138803d342f319d9ca9ff8.mDMe8UQ7P9KZbnTQ")
# 循环提问/对话
while True:
    # 接收用户输入作为问题
    prompt = input("\nuser:")
    response = client.chat.completions.create(
        model="glm-4",  # 填写需要调用的模型名称
        messages=[
            {"role": "user", "content": prompt}
        ],
    )
    answer = response.choices[0].message.content
    print("\nZhipuAI:", answer)  # 只输出大模型响应的message.context
