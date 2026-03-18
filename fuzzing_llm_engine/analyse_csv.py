import pandas as pd
import numpy as np

# === 配置 ===
file_path = '/home/op/CKGFuzzer/fuzzing_llm_engine/external_database/lcms/api_combine/combined_call_graph.csv'  # 修改这里

print(f"正在读取 {file_path} ... (可能需要几秒钟)")
# 只读取前两列，加快速度
df = pd.read_csv(file_path, usecols=['caller', 'callee'])

print(f"总行数: {len(df)}")

# 统计每个 API 作为“调用者”出现了多少次
caller_counts = df['caller'].value_counts()
# 统计每个 API 作为“被调用者”出现了多少次
callee_counts = df['callee'].value_counts()

# 合并统计 (即一个 API 总共涉及多少行)
total_connections = caller_counts.add(callee_counts, fill_value=0).sort_values(ascending=False)

print("\n" + "="*40)
print("API 复杂度分析报告")
print("="*40)
print(f"涉及 API 总数: {len(total_connections)}")
print(f"单个 API 最大连接数: {int(total_connections.max())}")
print(f"单个 API 平均连接数: {total_connections.mean():.2f}")
print(f"单个 API 中位数: {total_connections.median()}")
print("-" * 40)

# 分位数统计
print("分布情况:")
print(f"90% 的 API 连接数少于: {int(np.percentile(total_connections, 90))}")
print(f"95% 的 API 连接数少于: {int(np.percentile(total_connections, 95))}")
print(f"99% 的 API 连接数少于: {int(np.percentile(total_connections, 99))}")

print("-" * 40)
print("连接数最多的 Top 10 API (即最可能被切片影响的):")
print(total_connections.head(10))