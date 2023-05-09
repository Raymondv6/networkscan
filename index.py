# Import necessary libraries
from tkinter import *
from scapy.all import srp, Ether, ARP, IP, TCP, sr1

# Define a list of authorized users and their roles
authorized_users = {
    "user1": "admin",
    "user2": "viewer"
}

# Define the result_text variable as a global variable
global result_text
result_text = None

def scan_network():
    global result_text

    # Get the IP address and port range from input fields
    target_ip = ip_entry.get()
    port_range = (int(port_start_entry.get()), int(port_end_entry.get()))

    # Send packets to all devices on the network asking for their MAC addresses using ARP
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=2, retry=1)

  # Scan each alive device for open ports using a SYN scan
    for sent, received in ans:
        ip = received.psrc
        for port in range(port_range[0], port_range[1]+1):
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=1, verbose=0)
            if response:
                result_text.insert(END, f"{ip}:{port} is open\n")

# Create the main window and input fields and labels as global variables so they can be accessed from within functions.
global username_entry, root, ip_entry

root = Tk()
root.title("Network Scanner")

username_label = Label(root,text="Username:")
username_label.grid(row=0,column=0)
username_entry = Entry(root)
username_entry.grid(row=0,column=1)

ip_label = Label(root,text="Target IP address:")
ip_label.grid(row=1,column=0)
ip_entry = Entry(root)
ip_entry.grid(row=1,column=1)

port_start_label = Label(root,text="Start Port:")
port_start_label.grid(row=2,column=0)
port_start_entry = Entry(root)
port_start_entry.grid(row=2,column=1)

port_end_label = Label(root,text="End Port:")
port_end_label.grid(row=3,column=0)
port_end_entry = Entry(root)
port_end_entry.grid(row=3,column=1)

# Create the scan button
scan_button = Button(root,text="Scan Network",command=lambda: scan_network())
scan_button.grid(row=4,columnspan=2)

# Create the result text area if it doesn't exist yet.
if not result_text:
    result_label = Label(root,text="Scan Results:")
    result_label.grid(row=5,columnspan=2)
    result_text = Text(root,height=10,width=50)
    result_text.grid(row=6,columnspan=2)

    username = username_entry.get().strip()
    print(f"Username entered: {username}")
    print(f"Authorized users: {authorized_users}")
    if username in authorized_users:
        # User is authorized - do something here
        pass
    else:
        if result_text:
            result_text.delete("1.0", END)
            result_text.insert(END,f"Access denied for user {username}")


# Create the result text area if it doesn't exist yet.
if not result_text:
    result_label = Label(root,text="Scan Results:")
    result_label.grid(row=5,columnspan=2)
    result_text = Text(root,height=10,width=50)
    result_text.grid(row=6,columnspan=2)

# Clear previous results before displaying new ones
result_text.delete("1.0", END)

# Start the main event loop
root.mainloop()
