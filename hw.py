import dns.resolver

answers = dns.resolver.resolve("google.com", "A")

for answer in answers:
    print(answer)