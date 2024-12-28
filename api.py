import random
import secrets
import psycopg2
import time

def update():
    conn = psycopg2.connect(
            dbname='antivirus_db',  # Имя базы данных
            user='postgres',    # Имя пользователя
            password='123456P@$$', # Пароль
            host='localhost',     # Хост
            port='5432'                    # Порт по умолчанию
        )
        
    with conn.cursor() as cur:
        i = 0
        while True:
            sig = secrets.token_hex()
            desk = ['DarkPhantom', ' CryptoClaw', ' RogueViper', ' SilentReaper', ' ShadowStrike', ' VenomHunter', ' NetWrangler', ' StealthFang', ' OblivionKey', ' BlackMist', ' FireStorm', ' GhostEcho', ' HexBlade', ' NightWorm', ' SilverScythe', ' BloodHaze', ' CobaltSpecter', ' WraithFlare', ' IronJester', ' DreadSpire', ' FrostRage', ' EclipseWorm', ' PhantomLock', ' CerberusClaw', ' BlackWidow', ' StormBolt', ' ScarletViper', ' MidnightBite', ' FallenAngel', ' RustKnight', ' BlueFang', ' NullTerror', ' VoidWalker', ' DarkWeb', ' CrimsonSpike', ' GraveMist', ' PixelReaper', ' ByteBerserk', ' ChaosVortex', ' DeepHollow']
    
            cur.execute(f"INSERT INTO signatures (signature,description) VALUES('{sig}','{desk[i%40]}');")
            conn.commit()
            i += 1
            print("[INFO] Данные добавлены")
            if i % 40 == 0: time.sleep(10)
    
    
