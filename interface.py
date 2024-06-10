from classical import Classical
from modern import Modern

if __name__ == "__main__":
    print("Welcome to cryptography 102\n")
    print("This program allows you to encrypt messages in both classical and modern cryptographic methods.\n")
    print("Choose an option: \n")
    print("1. Classical method \n")
    print("2. Modern Method \n")
    print("3. End program \n\n")



    while True:
        x = input("Enter your choice (1,2,3): ")
        print("\n")

        if (x == '1'):
            cipher_text = Classical()
            print("Ciphertext: ",cipher_text)
            print("\n")

        elif (x =='2'):
            new_plain_text = Modern()
            print("Plaintext: ",new_plain_text)
            print("\n")

        elif( x == '3'):
            print("Have a nice day. Best reagrds, Rudra More")
            print("\n")
            break

        else:
            print("Invalid Input \n")
            x = input("Enter only either these choices (1,2,3): ")
            print("\n")
