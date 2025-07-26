# main.py

from detector.analyze import analyze_url

def main():
    url = input("Enter a URL to check: ")
    result = analyze_url(url)
    
    print("\n--- Analysis Result ---")
    print(f"URL: {result['url']}")
    print(f"Phishing Score: {result['score']}/5")
    print("Reasons:")
    for reason in result['reasons']:
        print(f" - {reason}")

if __name__ == "__main__":
    main()
