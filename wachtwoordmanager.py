"""
Wachtwoordmanager voor Windows
Vereist: Python 3.8+ met 'cryptography' package
Installeer: pip install cryptography
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import secrets
import string
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes



DATA_DIR = Path(os.getenv("APPDATA", Path.home())) / "Wachtwoordmanager"
DATA_FILE = DATA_DIR / "kluis.enc"
SALT_FILE = DATA_DIR / "salt.bin"
DATA_DIR.mkdir(parents=True, exist_ok=True)



def maak_sleutel(wachtwoord: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    sleutel = base64.urlsafe_b64encode(kdf.derive(wachtwoord.encode()))
    return Fernet(sleutel)


def laad_data(wachtwoord: str):
    if not DATA_FILE.exists():
        return {}
    salt = SALT_FILE.read_bytes()
    f = maak_sleutel(wachtwoord, salt)
    try:
        versleuteld = DATA_FILE.read_bytes()
        return json.loads(f.decrypt(versleuteld).decode())
    except Exception:
        return None  # Verkeerd wachtwoord


def sla_data_op(data: dict, wachtwoord: str):
    if not SALT_FILE.exists():
        SALT_FILE.write_bytes(os.urandom(16))
    salt = SALT_FILE.read_bytes()
    f = maak_sleutel(wachtwoord, salt)
    DATA_FILE.write_bytes(f.encrypt(json.dumps(data, ensure_ascii=False).encode()))


def genereer_wachtwoord(lengte=16, symbolen=True):
    tekens = string.ascii_letters + string.digits
    if symbolen:
        tekens += "!@#$%^&*()-_=+"
    return "".join(secrets.choice(tekens) for _ in range(lengte))



class WachtwoordManager(tk.Tk):
    BLAUW = "#1a73e8"
    DONKER = "#202124"
    GRIJS  = "#f1f3f4"
    WIT    = "#ffffff"
    ROOD   = "#d93025"
    GROEN  = "#1e8e3e"

    def __init__(self):
        super().__init__()
        self.title("Wachtwoordmanager")
        self.geometry("860x580")
        self.minsize(720, 480)
        self.configure(bg=self.WIT)
        self.resizable(True, True)

        self.hoofd_wachtwoord = None
        self.data: dict = {}
        self.geselecteerde_id = None
        self._kopieer_timer = None

        self._stijl()
        self._toon_login()


    def _stijl(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TFrame", background=self.WIT)
        s.configure("Zijbalk.TFrame", background=self.GRIJS)
        s.configure("TLabel", background=self.WIT, foreground=self.DONKER,
                    font=("Segoe UI", 10))
        s.configure("Titel.TLabel", font=("Segoe UI", 22, "bold"),
                    foreground=self.BLAUW, background=self.WIT)
        s.configure("Klein.TLabel", font=("Segoe UI", 9),
                    foreground="#5f6368", background=self.WIT)
        s.configure("TButton", font=("Segoe UI", 10), padding=6,
                    relief="flat", background=self.BLAUW, foreground=self.WIT)
        s.map("TButton",
              background=[("active", "#1558b0"), ("disabled", "#bdc1c6")],
              foreground=[("disabled", self.WIT)])
        s.configure("Wit.TButton", background=self.WIT, foreground=self.DONKER,
                    relief="solid", borderwidth=1)
        s.map("Wit.TButton",
              background=[("active", self.GRIJS)],
              foreground=[("active", self.DONKER)])
        s.configure("Rood.TButton", background=self.ROOD, foreground=self.WIT)
        s.map("Rood.TButton", background=[("active", "#b7261f")])
        s.configure("TEntry", fieldbackground=self.WIT, font=("Segoe UI", 10),
                    padding=4)
        s.configure("Treeview", font=("Segoe UI", 10), rowheight=30,
                    background=self.WIT, fieldbackground=self.WIT,
                    foreground=self.DONKER)
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"),
                    background=self.GRIJS, foreground=self.DONKER, relief="flat")
        s.map("Treeview", background=[("selected", "#e8f0fe")],
              foreground=[("selected", self.DONKER)])

    def _toon_login(self):
        self._leeg()
        frame = ttk.Frame(self)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="🔑 Wachtwoordmanager", style="Titel.TLabel").pack(pady=(0, 6))
        nieuw = not DATA_FILE.exists()
        tekst = ("Maak een hoofdwachtwoord aan om te beginnen."
                 if nieuw else "Voer je hoofdwachtwoord in.")
        ttk.Label(frame, text=tekst, style="Klein.TLabel").pack(pady=(0, 20))

        invoer_frame = ttk.Frame(frame)
        invoer_frame.pack(fill="x", pady=4)
        ttk.Label(invoer_frame, text="Hoofdwachtwoord").pack(anchor="w")
        self._pw_var = tk.StringVar()
        pw_entry = ttk.Entry(invoer_frame, textvariable=self._pw_var,
                             show="●", width=34, font=("Segoe UI", 11))
        pw_entry.pack(fill="x", ipady=4)
        pw_entry.focus_set()

        if nieuw:
            ttk.Label(invoer_frame, text="Herhaal wachtwoord",
                      style="Klein.TLabel").pack(anchor="w", pady=(8, 0))
            self._pw2_var = tk.StringVar()
            ttk.Entry(invoer_frame, textvariable=self._pw2_var,
                      show="●", width=34, font=("Segoe UI", 11)).pack(fill="x", ipady=4)

        knop_tekst = "Kluis aanmaken" if nieuw else "Openen"
        ttk.Button(frame, text=knop_tekst,
                   command=self._doe_login).pack(fill="x", pady=(18, 0), ipady=4)
        self.bind("<Return>", lambda e: self._doe_login())

    def _doe_login(self):
        pw = self._pw_var.get()
        if not pw:
            messagebox.showwarning("Leeg", "Vul een hoofdwachtwoord in.")
            return

        if not DATA_FILE.exists():
            pw2 = self._pw2_var.get()
            if pw != pw2:
                messagebox.showerror("Fout", "Wachtwoorden komen niet overeen.")
                return
            if len(pw) < 6:
                messagebox.showwarning("Te kort",
                                       "Kies een wachtwoord van minimaal 6 tekens.")
                return
            self.data = {}
            sla_data_op(self.data, pw)
            self.hoofd_wachtwoord = pw
            self._toon_hoofd()
        else:
            resultaat = laad_data(pw)
            if resultaat is None:
                messagebox.showerror("Onjuist", "Verkeerd hoofdwachtwoord.")
                return
            self.data = resultaat
            self.hoofd_wachtwoord = pw
            self._toon_hoofd()


    def _toon_hoofd(self):
        self._leeg()
        self.unbind("<Return>")

        # Bovenbalk
        balk = tk.Frame(self, bg=self.BLAUW, height=52)
        balk.pack(fill="x")
        balk.pack_propagate(False)
        tk.Label(balk, text="  🔑 Wachtwoordmanager", bg=self.BLAUW,
                 fg=self.WIT, font=("Segoe UI", 13, "bold")).pack(side="left",
                                                                   padx=10, pady=12)
        ttk.Button(balk, text="Vergrendelen",
                   command=self._vergrendel, style="Wit.TButton").pack(
            side="right", padx=10, pady=10)

        # Hoofdgebied: twee kolommen
        hoofd = ttk.Frame(self)
        hoofd.pack(fill="both", expand=True)

        # Linker zijbalk
        zijbalk = ttk.Frame(hoofd, style="Zijbalk.TFrame", width=200)
        zijbalk.pack(side="left", fill="y")
        zijbalk.pack_propagate(False)

        tk.Label(zijbalk, text="Zoeken", bg=self.GRIJS,
                 font=("Segoe UI", 9), fg="#5f6368").pack(anchor="w", padx=12, pady=(14, 2))
        self._zoek_var = tk.StringVar()
        self._zoek_var.trace_add("write", lambda *_: self._filter_lijst())
        zoek = ttk.Entry(zijbalk, textvariable=self._zoek_var, width=22)
        zoek.pack(padx=10, pady=(0, 10), fill="x")

        ttk.Button(zijbalk, text="＋  Nieuw item",
                   command=self._nieuw_item).pack(padx=10, pady=4, fill="x")

        tk.Label(zijbalk, text="ITEMS", bg=self.GRIJS,
                 font=("Segoe UI", 8, "bold"), fg="#5f6368").pack(
            anchor="w", padx=12, pady=(12, 4))

        lijst_frame = tk.Frame(zijbalk, bg=self.GRIJS)
        lijst_frame.pack(fill="both", expand=True, padx=6)
        self._lijst = tk.Listbox(lijst_frame, font=("Segoe UI", 10),
                                 bg=self.GRIJS, bd=0, highlightthickness=0,
                                 selectbackground="#e8f0fe",
                                 selectforeground=self.DONKER,
                                 activestyle="none", cursor="hand2")
        sb = ttk.Scrollbar(lijst_frame, orient="vertical",
                           command=self._lijst.yview)
        self._lijst.configure(yscrollcommand=sb.set)
        self._lijst.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._lijst.bind("<<ListboxSelect>>", self._selecteer)

        # Rechter detailvenster
        self._detail = ttk.Frame(hoofd)
        self._detail.pack(side="left", fill="both", expand=True, padx=20, pady=20)

        self._vul_lijst()
        self._toon_welkom()

    def _vul_lijst(self, filter_tekst=""):
        self._lijst.delete(0, "end")
        self._zichtbare_ids = []
        for uid, item in sorted(self.data.items(),
                                key=lambda x: x[1].get("naam", "").lower()):
            naam = item.get("naam", "Naamloos")
            if filter_tekst.lower() in naam.lower():
                self._lijst.insert("end", f"  {naam}")
                self._zichtbare_ids.append(uid)

    def _filter_lijst(self):
        zoek = self._zoek_var.get()
        huidig = self.geselecteerde_id
        self._vul_lijst(zoek)
        if huidig in self._zichtbare_ids:
            idx = self._zichtbare_ids.index(huidig)
            self._lijst.selection_set(idx)

    def _selecteer(self, _event=None):
        sel = self._lijst.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx < len(self._zichtbare_ids):
            self.geselecteerde_id = self._zichtbare_ids[idx]
            self._toon_detail(self.geselecteerde_id)


    def _leeg_detail(self):
        for w in self._detail.winfo_children():
            w.destroy()

    def _toon_welkom(self):
        self._leeg_detail()
        tk.Label(self._detail,
                 text=f"Je kluis bevat {len(self.data)} item(s).\nSelecteer een item of maak een nieuw aan.",
                 font=("Segoe UI", 11), fg="#5f6368", bg=self.WIT,
                 justify="center").pack(expand=True)

    def _toon_detail(self, uid):
        self._leeg_detail()
        item = self.data.get(uid, {})

        # Naam als koptekst
        naam_var = tk.StringVar(value=item.get("naam", ""))
        ttk.Label(self._detail, text="Naam").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(self._detail, textvariable=naam_var, width=38,
                  font=("Segoe UI", 10)).grid(row=0, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(self._detail, text="Gebruikersnaam").grid(row=1, column=0, sticky="w", pady=4)
        user_var = tk.StringVar(value=item.get("gebruikersnaam", ""))
        gebruiker_entry = ttk.Entry(self._detail, textvariable=user_var, width=38)
        gebruiker_entry.grid(row=1, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(self._detail, text="Wachtwoord").grid(row=2, column=0, sticky="w", pady=4)
        pw_var = tk.StringVar(value=item.get("wachtwoord", ""))
        pw_frame = ttk.Frame(self._detail)
        pw_frame.grid(row=2, column=1, sticky="ew", pady=4, padx=(8, 0))
        pw_entry = ttk.Entry(pw_frame, textvariable=pw_var, show="●", width=28)
        pw_entry.pack(side="left")
        toon_var = tk.BooleanVar(value=False)

        def wissel_toon():
            pw_entry.config(show="" if toon_var.get() else "●")
        ttk.Checkbutton(pw_frame, text="Toon", variable=toon_var,
                        command=wissel_toon).pack(side="left", padx=4)

        ttk.Label(self._detail, text="Website / URL").grid(row=3, column=0, sticky="w", pady=4)
        url_var = tk.StringVar(value=item.get("url", ""))
        ttk.Entry(self._detail, textvariable=url_var, width=38).grid(
            row=3, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(self._detail, text="Notities").grid(row=4, column=0, sticky="nw", pady=4)
        notities = tk.Text(self._detail, width=38, height=5, font=("Segoe UI", 10),
                           wrap="word", relief="solid", bd=1)
        notities.insert("1.0", item.get("notities", ""))
        notities.grid(row=4, column=1, sticky="ew", pady=4, padx=(8, 0))

        self._detail.columnconfigure(1, weight=1)

        # Generator
        gen_frame = ttk.Frame(self._detail)
        gen_frame.grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 4))
        ttk.Label(gen_frame, text="Generator:").pack(side="left")
        lengte_var = tk.IntVar(value=16)
        ttk.Spinbox(gen_frame, from_=8, to=64, textvariable=lengte_var,
                    width=4).pack(side="left", padx=4)
        ttk.Label(gen_frame, text="tekens").pack(side="left")
        symbolen_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(gen_frame, text="Symbolen",
                        variable=symbolen_var).pack(side="left", padx=8)

        def genereer():
            nieuw = genereer_wachtwoord(lengte_var.get(), symbolen_var.get())
            pw_var.set(nieuw)
            pw_entry.config(show="")
            toon_var.set(True)

        ttk.Button(gen_frame, text="Genereer",
                   command=genereer, style="Wit.TButton").pack(side="left")

        # Knoppen
        knop_frame = ttk.Frame(self._detail)
        knop_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(16, 0))

        self._status_label = ttk.Label(knop_frame, text="", style="Klein.TLabel",
                                       foreground=self.GROEN)
        self._status_label.pack(side="left")

        def kopieer_pw():
            self.clipboard_clear()
            self.clipboard_append(pw_var.get())
            self._toon_status("Wachtwoord gekopieerd!")

        def opslaan():
            item["naam"]            = naam_var.get().strip() or "Naamloos"
            item["gebruikersnaam"]  = user_var.get().strip()
            item["wachtwoord"]      = pw_var.get()
            item["url"]             = url_var.get().strip()
            item["notities"]        = notities.get("1.0", "end-1c")
            self.data[uid] = item
            sla_data_op(self.data, self.hoofd_wachtwoord)
            self._vul_lijst(self._zoek_var.get())
            if uid in self._zichtbare_ids:
                idx = self._zichtbare_ids.index(uid)
                self._lijst.selection_set(idx)
            self._toon_status("✓  Opgeslagen")

        def verwijder():
            naam = item.get("naam", "dit item")
            if messagebox.askyesno("Verwijderen",
                                   f"'{naam}' definitief verwijderen?",
                                   icon="warning"):
                del self.data[uid]
                sla_data_op(self.data, self.hoofd_wachtwoord)
                self.geselecteerde_id = None
                self._vul_lijst(self._zoek_var.get())
                self._toon_welkom()

        ttk.Button(knop_frame, text="Kopieer wachtwoord",
                   command=kopieer_pw, style="Wit.TButton").pack(side="right", padx=4)
        ttk.Button(knop_frame, text="Verwijderen",
                   command=verwijder, style="Rood.TButton").pack(side="right", padx=4)
        ttk.Button(knop_frame, text="Opslaan",
                   command=opslaan).pack(side="right", padx=4)

    def _toon_status(self, tekst):
        if self._kopieer_timer:
            self.after_cancel(self._kopieer_timer)
        self._status_label.config(text=tekst)
        self._kopieer_timer = self.after(2500, lambda: self._status_label.config(text=""))

   
    def _nieuw_item(self):
        uid = secrets.token_hex(8)
        self.data[uid] = {
            "naam": "Nieuw item",
            "gebruikersnaam": "",
            "wachtwoord": "",
            "url": "",
            "notities": "",
        }
        sla_data_op(self.data, self.hoofd_wachtwoord)
        self._vul_lijst(self._zoek_var.get())
        self.geselecteerde_id = uid
        if uid in self._zichtbare_ids:
            idx = self._zichtbare_ids.index(uid)
            self._lijst.selection_set(idx)
            self._lijst.see(idx)
        self._toon_detail(uid)


    def _vergrendel(self):
        self.hoofd_wachtwoord = None
        self.data = {}
        self.geselecteerde_id = None
        self._toon_login()


    def _leeg(self):
        for w in self.winfo_children():
            w.destroy()


if __name__ == "__main__":
    app = WachtwoordManager()
    app.mainloop()
