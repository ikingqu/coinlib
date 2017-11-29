package utils

func round(f float64) float64 {
	return float64(f*100000000) / 100000000
}

// CoinToFloat converts coin to float64.
func CoinToFloat(val *big.Int) float64 {
	bigval := new(big.Float)
	bigval.SetInt(val)

	coin := new(big.Float)
	coin.SetInt(params.Params.Coin)
	bigval.Quo(bigval, coin)

	fCoin, _ := bigval.Float64()
	return round(fCoin)
}

// FloatToCoin coverts float64 to coin.
func FloatToCoin(val float64) *big.Int {
	bigval := new(big.Float)
	bigval.SetFloat64(val)
	bigval.SetPrec(64)

	coin := new(big.Float)
	coin.SetInt(params.Params.Coin)
	bigval.Mul(bigval, coin)

	result := new(big.Int)
	bigval.Int(result)

	return result
}
