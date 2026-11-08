"""Exports the pages of the `dataset` database (with module and OS) to Parquet.

Usage: python export_db.py OUT_DIR [HOST]
"""
import os
import sys

import mysql.connector
import pyarrow as pa
import pyarrow.parquet as pq

QUERY = """
SELECT p.id AS page_id, p.num_page, p.hashTLSH AS tlsh, p.hashSSDEEP AS ssdeep,
       p.hashSDHASH AS sdhash_db, p.module_id, m.original_filename, m.internal_filename,
       m.file_version, m.cpu, m.file_path, o.version AS os_version, o.name AS os_name
FROM pages p JOIN modules m ON m.id = p.module_id JOIN os o ON o.id = m.os_id
"""
BATCH = 200_000


def main():
    out = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else "sda-mariadb"
    os.makedirs(out, exist_ok=True)
    db = mysql.connector.connect(host=host, user="root", database="dataset")
    cur = db.cursor()
    cur.execute(QUERY)
    cols = [d[0] for d in cur.description]
    writer = None
    total = 0
    while rows := cur.fetchmany(BATCH):
        data = {c: [r[i] for r in rows] for i, c in enumerate(cols)}
        # The DB sdhash has an empty name ("sdbf:03:0::<size>:..."): it is kept from the size onwards
        data["sdhash"] = [s.split(":", 4)[4] for s in data.pop("sdhash_db")]
        table = pa.table(data)
        if writer is None:
            writer = pq.ParquetWriter(os.path.join(out, "db_pages.parquet"), table.schema, compression="zstd")
        writer.write_table(table)
        total += len(rows)
        print(f"{total} páginas exportadas", flush=True)
    writer.close()


if __name__ == "__main__":
    main()
