import sqlite3

# 连接到SQLite数据库
# 如果文件不存在，会自动在当前目录创建:
conn = sqlite3.connect('students.db')
cursor = conn.cursor()
# 使用PRAGMA命令查看表结构
cursor.execute("PRAGMA table_info(students)")
columns = cursor.fetchall()
# 打印表结构
for column in columns:
    print(column)
# 关闭Cursor和Connection:
cursor.close()
conn.close()
