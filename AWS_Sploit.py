import os

def logo():
    print("\033[1;32m" + """
  ______   __       __   ______         ______   _______   __        ______   ______  ________ 
 /      \ |  \  _  |  \ /      \       /      \ |       \ |  \      /      \ |      \|        \\
|  $$$$$$\| $$ / \ | $$|  $$$$$$\     |  $$$$$$\| $$$$$$$\| $$     |  $$$$$$\ \$$$$$$ \$$$$$$$$
| $$__| $$| $$/  $\| $$| $$___\$$     | $$___\$$| $$__/ $$| $$     | $$  | $$  | $$     | $$   
| $$    $$| $$  $$$\ $$ \$$    \       \$$    \ | $$    $$| $$     | $$  | $$  | $$     | $$   
| $$$$$$$$| $$ $$\$$\$$ _\$$$$$$\      _\$$$$$$\| $$$$$$$ | $$     | $$  | $$  | $$     | $$   
| $$  | $$| $$$$  \$$$$|  \__| $$     |  \__| $$| $$      | $$_____| $$__/ $$ _| $$_    | $$   
| $$  | $$| $$$    \$$$ \$$    $$______\$$    $$| $$      | $$     \\$$    $$|   $$ \   | $$   
 \$$   \$$ \$$      \$$  \$$$$$$|      \\$$$$$$  \$$       \$$$$$$$$ \$$$$$$  \$$$$$$    \$$   
                                 \$$$$$$                                                                                                  
                                            """ + "\033[1;34m" + "LET'S SCAN THE CLOUD\n")



def ec2_configuration_scan():
    # Run ec2sploit.py
    os.system("python tools/EC2Sploit.py")

def s3_configuration_scan():
    # Run s3sploit.py
    os.system("python tools/S3Sploit.py")

def main():
    while True:
        logo()
        print("1. EC2 Configuration Scan")
        print("2. S3 Configuration Scan")
        print("3. Close")

        choice = input("Enter your choice: ")

        if choice == '1':
            ec2_configuration_scan()
        elif choice == '2':
            s3_configuration_scan()
        elif choice == '3':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please select again.")

if __name__ == "__main__":
    main()
