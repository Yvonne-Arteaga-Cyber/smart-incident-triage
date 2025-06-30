import pandas as pd

log_file = 'C:/Users/yvonn/OneDrive/Documents/Project- smart-incident-triage/sample_logs/sample_firewall_log.csv'
df = pd.read_csv(log_file)

print("\n📄 All Log Entries:\n")
print(df)

sensitive_ports = [22, 3389]

def score_row(row):
    score = 0
    if row['action'].strip() == 'DENY':
        score += 1
        if row['port'] in sensitive_ports:
            score += 2
    return score

df['suspicion_score'] = df.apply(score_row, axis=1)

suspicious = df[df['suspicion_score'] >= 2]

print("\n🚨 Suspicious Entries:\n")
print(suspicious)

suspicious.to_csv('suspicious_activity_output.csv', index=False)
print("\n✅ Suspicious entries saved to: suspicious_activity_output.csv")
