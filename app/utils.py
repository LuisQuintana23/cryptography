from Crypto.Protocol.SecretSharing import Shamir

def create_shares(secret_bytes: bytes, threshold: int, num_shares: int) -> list[str]:
    part1 = secret_bytes[:16]
    part2 = secret_bytes[16:]
    shares1 = Shamir.split(threshold, num_shares, part1)
    shares2 = Shamir.split(threshold, num_shares, part2)
    final_shares = []
    for i in range(num_shares):
        idx = shares1[i][0] 
        combined_data = shares1[i][1] + shares2[i][1]
        final_shares.append(f"{idx}:{combined_data.hex()}")
    return final_shares

def reconstruct_key(shares_list: list[str]) -> bytes:
    shares1, shares2 = [], []
    for share_str in shares_list:
        idx_str, data_hex = share_str.split(':')
        idx = int(idx_str)
        data_bytes = bytes.fromhex(data_hex)
        shares1.append((idx, data_bytes[:16]))
        shares2.append((idx, data_bytes[16:]))
    return Shamir.combine(shares1) + Shamir.combine(shares2)