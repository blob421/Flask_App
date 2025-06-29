def serialize_row(row):
    return {
        "date": row[0].isoformat(),
        "price": float(row[1]),
        "volume": float(row[2]),
        "market_cap": float(row[3]),
        "availablesupply": float(row[4]),
        "totalsupply": int(row[5]),
        "fullyDilutedValuation": float(row[6]),
        "priceChange1h": float(row[7]),
        "priceChange1d": float(row[8]),
        "priceChange1w": float(row[9])
        
        }
        