import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import hashlib

class DigitalSignerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signer ✨")
        self.root.config(bg="#e0f7fa")

        self.container = tk.Frame(self.root, bg="#e0f7fa")
        self.container.pack(expand=True, fill="both", padx=20, pady=20)

        self.frames = {}
        for F in (KeyGenPage, HomePage, HashPage, SignPage, VerifyPage):
            frame = F(self.container, self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.file_path = None
        self.hash_value = None
        self.signature = None
        self.private_key = None
        self.public_key = None

        self.show_frame("KeyGenPage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        if page_name == "HashPage" and self.hash_value:
            frame.update_hash(self.hash_value)
        frame.tkraise()

    def generate_key_pair(self):
        key = RSA.generate(2048)
        self.private_key = key.export_key().decode('utf-8')  # Convert to string for display
        self.public_key = key.publickey().export_key().decode('utf-8')  # Convert to string for display
        return self.private_key, self.public_key

    def hash_file(self, file_path):
        h = hashlib.sha512()
        with open(file_path, 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                h.update(chunk)
        return h.hexdigest()

class KeyGenPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#e0f7fa")
        title_label = tk.Label(self, text="🔑 Key Generation", font=("Segoe UI", 20, "bold"), 
                               bg="#e0f7fa", fg="#00695c")
        title_label.pack(pady=10)

        self.status_label = tk.Label(self, text="Click to generate keys...", font=("Segoe UI", 12), 
                                     bg="#e0f7fa", fg="#424242")
        self.status_label.pack(pady=10)

        # Text widgets for displaying keys
        self.pub_key_display = tk.Text(self, height=4, width=50, font=("Segoe UI", 10), wrap="word", bg="#ffffff", fg="#424242")
        self.pub_key_display.pack(pady=5)
        self.pub_key_display.insert(tk.END, "Public Key will appear here...")
        self.pub_key_display.config(state="disabled")

        self.priv_key_display = tk.Text(self, height=4, width=50, font=("Segoe UI", 10), wrap="word", bg="#ffffff", fg="#424242")
        self.priv_key_display.pack(pady=5)
        self.priv_key_display.insert(tk.END, "Private Key will appear here...")
        self.priv_key_display.config(state="disabled")

        gen_button = tk.Button(self, text="🔧 Generate Keys", command=lambda: self.generate_keys(controller), 
                               font=("Segoe UI", 12, "bold"), bg="#26a69a", fg="white", width=20, relief="flat", cursor="hand2")
        gen_button.pack(pady=10)
        gen_button.bind("<Enter>", lambda e: gen_button.config(bg="#80cbc4"))
        gen_button.bind("<Leave>", lambda e: gen_button.config(bg="#26a69a"))

        next_button = tk.Button(self, text="➡️ Next", command=lambda: controller.show_frame("HomePage"), 
                                font=("Segoe UI", 12, "bold"), bg="#ff9800", fg="white", width=20, relief="flat", cursor="hand2")
        next_button.pack(pady=10)
        next_button.bind("<Enter>", lambda e: next_button.config(bg="#ffb300"))
        next_button.bind("<Leave>", lambda e: next_button.config(bg="#ff9800"))

    def generate_keys(self, controller):
        self.status_label.config(text="Generating keys... ⏳")
        private_key, public_key = controller.generate_key_pair()
        
        # Update public key display
        self.pub_key_display.config(state="normal")
        self.pub_key_display.delete(1.0, tk.END)
        self.pub_key_display.insert(tk.END, public_key)
        self.pub_key_display.config(state="disabled")

        # Update private key display
        self.priv_key_display.config(state="normal")
        self.priv_key_display.delete(1.0, tk.END)
        self.priv_key_display.insert(tk.END, private_key)
        self.priv_key_display.config(state="disabled")

        # Prompt to save public key
        pub_key_path = filedialog.asksaveasfilename(defaultextension=".pem",
                                                    filetypes=[("PEM Files", "*.pem")],
                                                    title="Save Public Key As",
                                                    initialfile="public_key.pem")
        if pub_key_path:
            with open(pub_key_path, "wb") as pub_file:
                pub_file.write(public_key.encode('utf-8'))
            self.status_label.config(text="Keys generated! Public key saved. 🎉")
        else:
            self.status_label.config(text="Keys generated, but public key not saved. 😕")

class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#e0f7fa")
        title_label = tk.Label(self, text="✨ Digital Signer App ✨", font=("Segoe UI", 24, "bold"), 
                               bg="#e0f7fa", fg="#00695c")
        title_label.pack(pady=15)

        self.status_label = tk.Label(self, text="Ready to sign!", font=("Segoe UI", 12), 
                                     bg="#e0f7fa", fg="#424242")
        self.status_label.pack(pady=10)

        upload_button = tk.Button(self, text="📤 Upload File", command=lambda: self.upload_file(controller), 
                                  font=("Segoe UI", 12, "bold"), bg="#26a69a", fg="white", width=20, relief="flat", cursor="hand2")
        upload_button.pack(pady=20)
        upload_button.bind("<Enter>", lambda e: upload_button.config(bg="#80cbc4"))
        upload_button.bind("<Leave>", lambda e: upload_button.config(bg="#26a69a"))

    def upload_file(self, controller):
        controller.file_path = filedialog.askopenfilename(title="Select File")
        if controller.file_path:
            controller.hash_value = controller.hash_file(controller.file_path)
            self.status_label.config(text=f"File loaded: {controller.file_path.split('/')[-1]} 📜")
            controller.show_frame("HashPage")
        else:
            self.status_label.config(text="No file selected. Try again! 😕")

class HashPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#e0f7fa")
        title_label = tk.Label(self, text="🔍 File Hash", font=("Segoe UI", 20, "bold"), 
                               bg="#e0f7fa", fg="#00695c")
        title_label.pack(pady=10)

        self.hash_display = tk.Text(self, height=4, width=50, font=("Segoe UI", 10), wrap="word", bg="#ffffff", fg="#424242")
        self.hash_display.pack(pady=10)
        self.hash_display.config(state="disabled")

        button_frame = tk.Frame(self, bg="#e0f7fa")
        button_frame.pack(pady=20)

        back_button = tk.Button(button_frame, text="⬅️ Back", command=lambda: controller.show_frame("HomePage"), 
                                font=("Segoe UI", 12, "bold"), bg="#ff9800", fg="white", width=15, relief="flat", cursor="hand2")
        back_button.grid(row=0, column=0, padx=10)
        back_button.bind("<Enter>", lambda e: back_button.config(bg="#ffb300"))
        back_button.bind("<Leave>", lambda e: back_button.config(bg="#ff9800"))

        sign_button = tk.Button(button_frame, text="✍️ Sign", command=lambda: controller.show_frame("SignPage"), 
                                font=("Segoe UI", 12, "bold"), bg="#0288d1", fg="white", width=15, relief="flat", cursor="hand2")
        sign_button.grid(row=0, column=1, padx=10)
        sign_button.bind("<Enter>", lambda e: sign_button.config(bg="#4fc3f7"))
        sign_button.bind("<Leave>", lambda e: sign_button.config(bg="#0288d1"))

    def update_hash(self, hash_value):
        self.hash_display.config(state="normal")
        self.hash_display.delete(1.0, tk.END)
        self.hash_display.insert(tk.END, hash_value)
        self.hash_display.config(state="disabled")

class SignPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#e0f7fa")
        title_label = tk.Label(self, text="✍️ Sign Your File", font=("Segoe UI", 20, "bold"), 
                               bg="#e0f7fa", fg="#00695c")
        title_label.pack(pady=10)

        self.status_label = tk.Label(self, text="Ready to sign...", font=("Segoe UI", 12), 
                                     bg="#e0f7fa", fg="#424242")
        self.status_label.pack(pady=10)

        sign_button = tk.Button(self, text="✅ Sign Now", command=lambda: self.sign_file(controller), 
                                font=("Segoe UI", 12, "bold"), bg="#0288d1", fg="white", width=20, relief="flat", cursor="hand2")
        sign_button.pack(pady=10)
        sign_button.bind("<Enter>", lambda e: sign_button.config(bg="#4fc3f7"))
        sign_button.bind("<Leave>", lambda e: sign_button.config(bg="#0288d1"))

        back_button = tk.Button(self, text="⬅️ Back", command=lambda: controller.show_frame("HashPage"), 
                                font=("Segoe UI", 12, "bold"), bg="#ff9800", fg="white", width=20, relief="flat", cursor="hand2")
        back_button.pack(pady=10)
        back_button.bind("<Enter>", lambda e: back_button.config(bg="#ffb300"))
        back_button.bind("<Leave>", lambda e: back_button.config(bg="#ff9800"))

    def sign_file(self, controller):
        if not controller.file_path:
            messagebox.showerror("Error", "No file uploaded. 😞")
            return
        self.status_label.config(text="Signing in progress... ⏳")
        hash_obj = SHA512.new(controller.hash_value.encode())
        controller.signature = pkcs1_15.new(RSA.import_key(controller.private_key)).sign(hash_obj)

        signature_file_path = filedialog.asksaveasfilename(defaultextension=".sig",
                                                           filetypes=[("Signature Files", "*.sig")],
                                                           title="Save Signature As")
        if signature_file_path:
            with open(signature_file_path, "wb") as sig_file:
                sig_file.write(controller.signature)
            messagebox.showinfo("Success", f"File signed successfully! 🎉\nSignature saved as {signature_file_path}")
            self.status_label.config(text="File signed! Ready to verify. ✅")
            controller.show_frame("VerifyPage")
        else:
            self.status_label.config(text="Signature not saved. Try again! 😕")

class VerifyPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#e0f7fa")
        title_label = tk.Label(self, text="✅ Verify Signature", font=("Segoe UI", 20, "bold"), 
                               bg="#e0f7fa", fg="#00695c")
        title_label.pack(pady=10)

        self.status_label = tk.Label(self, text="Ready to verify...", font=("Segoe UI", 12), 
                                     bg="#e0f7fa", fg="#424242")
        self.status_label.pack(pady=10)

        verify_button = tk.Button(self, text="🔍 Verify Now", command=lambda: self.verify_file(controller), 
                                  font=("Segoe UI", 12, "bold"), bg="#d81b60", fg="white", width=20, relief="flat", cursor="hand2")
        verify_button.pack(pady=10)
        verify_button.bind("<Enter>", lambda e: verify_button.config(bg="#f06292"))
        verify_button.bind("<Leave>", lambda e: verify_button.config(bg="#d81b60"))

        back_button = tk.Button(self, text="⬅️ Back", command=lambda: controller.show_frame("SignPage"), 
                                font=("Segoe UI", 12, "bold"), bg="#ff9800", fg="white", width=20, relief="flat", cursor="hand2")
        back_button.pack(pady=10)
        back_button.bind("<Enter>", lambda e: back_button.config(bg="#ffb300"))
        back_button.bind("<Leave>", lambda e: back_button.config(bg="#ff9800"))

    def verify_file(self, controller):
        if not controller.file_path:
            messagebox.showerror("Error", "No file uploaded. 😞")
            return

        sig_file_path = filedialog.askopenfilename(title="Select Signature File",
                                                   filetypes=[("Signature Files", "*.sig")])
        if not sig_file_path:
            self.status_label.config(text="No signature file selected. 😕")
            return

        with open(sig_file_path, 'rb') as sig_file:
            signature = sig_file.read()

        pub_key_path = filedialog.askopenfilename(title="Select Public Key", 
                                                  filetypes=[("Public Key Files", "*.pem")])
        if not pub_key_path:
            self.status_label.config(text="No public key selected. 😕")
            return

        with open(pub_key_path, 'rb') as pub_file:
            public_key = pub_file.read()

        hash_obj = SHA512.new(controller.hash_value.encode())
        self.status_label.config(text="Verifying signature... ⏳")
        try:
            pkcs1_15.new(RSA.import_key(public_key)).verify(hash_obj, signature)
            messagebox.showinfo("Success", "The signature is valid! ✅")
            self.status_label.config(text="Signature verified successfully! 🎉")
        except (ValueError, TypeError):
            messagebox.showerror("Error", "The signature is not valid. ❌")
            self.status_label.config(text="Signature verification failed. 😞")

if __name__ == "__main__":
    root = tk.Tk()
    window_width, window_height = 600, 500  # Increased height to fit key display
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_x = int((screen_width / 2) - (window_width / 2))
    window_y = int((screen_height / 2) - (window_height / 2))
    root.geometry(f"{window_width}x{window_height}+{window_x}+{window_y}")
    root.resizable(True, True)
    app = DigitalSignerApp(root)
    root.mainloop()