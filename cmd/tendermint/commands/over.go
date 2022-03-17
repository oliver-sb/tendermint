package commands

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cosmos/btcutil/bech32"
	"github.com/gogo/protobuf/proto"
	"github.com/spf13/cobra"
	"github.com/tendermint/tendermint/internal/jsontypes"
	"github.com/tendermint/tendermint/libs/log"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"github.com/tendermint/tendermint/types"

	"github.com/valyala/fasthttp"
)

func NewOverCmd(logger log.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "over",
		Short: "over",
		Long:  fmt.Sprintf(`Generate Bash and Zsh completion scripts and print them to STDOUT.`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			run(logger)

			return nil
		},
	}

	return cmd
}

func getSignedHeader(data []byte, logger log.Logger) *types.SignedHeader {
	var resultBlock struct {
		BlockID types.BlockID `json:"block_id"`
		Block   struct {
			types.Header `json:"header"`
			LastCommit   *types.Commit `json:"last_commit"`
		} `json:"block"`
	}
	err := json.Unmarshal(data, &resultBlock)
	if err != nil {
		logger.Error("", "error", err)
		return nil
	}

	block := resultBlock.Block

	return &types.SignedHeader{
		Header: &block.Header,
		Commit: block.LastCommit,
	}
}

func getValidatorSet(data []byte, logger log.Logger) *types.ValidatorSet {
	var resultValset struct {
		Result struct {
			Validators []json.RawMessage `json:"validators"`
		} `json:"result"`
	}
	err := json.Unmarshal(data, &resultValset)
	if err != nil {
		logger.Error("Unmarshal 1", "error", err, "data", resultValset)
		return nil
	}

	valsets := []*types.Validator{}
	for _, d := range resultValset.Result.Validators {
		var v types.Validator = types.Validator{}

		var val struct {
			Address          string          `json:"address"`
			PubKey           json.RawMessage `json:"pub_key,omitempty"`
			VotingPower      int64           `json:"voting_power,string"`
			ProposerPriority int64           `json:"proposer_priority,string"`
		}
		err = json.Unmarshal(d, &val)
		if err != nil {
			return nil
		}
		if err := jsontypes.Unmarshal(val.PubKey, &v.PubKey); err != nil {
			return nil
		}
		_, v.Address, _ = DecodeAndConvert(string(val.Address))
		v.VotingPower = val.VotingPower
		v.ProposerPriority = val.ProposerPriority

		//jsonStr, _ := json.Marshal(v)
		//logger.Info("%s - %+v\n", string(v.Address), jsonStr)

		valsets = append(valsets, &v)
	}

	return &types.ValidatorSet{
		Validators: valsets,
		Proposer:   valsets[0],
	}
}

func getData(url string, logger log.Logger) []byte {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(url)
	req.Header.SetMethod("GET")

	resp := fasthttp.AcquireResponse()
	client := &fasthttp.Client{}
	defer client.CloseIdleConnections()
	defer resp.ConnectionClose()

	err := client.DoTimeout(req, resp, 10*time.Second)
	if err != nil {
		logger.Error("Error on RequestRPC : %+v\n", err)
		return nil
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		logger.Error("StatusCode not OK : %s\n", resp.String())
		return nil
	}

	return resp.Body()
}

func getValidators(url string, logger log.Logger) []*types.Validator {
	valsetData := getData(url, logger)
	return getValidatorSet(valsetData, logger).Validators
}

func DecodeAndConvert(bech string) (string, []byte, error) {
	hrp, data, err := bech32.Decode(bech, 1023)
	if err != nil {
		return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
	}

	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
	}

	return hrp, converted, nil
}

func run(logger log.Logger) {
	logger.Info("Run Over")

	host := "https://lcd.terra.dev"
	//host := "http://localhost:1317"

	blockData := getData(host+"/blocks/latest", logger)
	signedHeader := getSignedHeader(blockData, logger)
	url0 := fmt.Sprintf("%s/blocks/%d", host, signedHeader.Commit.Height)
	blockData = getData(url0, logger)
	signedHeader2 := getSignedHeader(blockData, logger)
	signedHeader.Header = signedHeader2.Header

	protoHeader := signedHeader.ToProto()

	byteData, err := proto.Marshal(protoHeader)
	if err != nil {
		logger.Error("", "error", err)
		return
	}

	header_proto := base64.RawStdEncoding.EncodeToString(byteData)
	logger.Info("", "encoded", len(header_proto), "byte data", len(byteData))

	url1 := fmt.Sprintf("%s/validatorsets/%d?page=1", host, signedHeader.Header.Height)
	valset1 := getValidators(url1, logger)

	url2 := fmt.Sprintf("%s/validatorsets/%d?page=2", host, signedHeader.Header.Height)
	valset2 := getValidators(url2, logger)

	valset := types.ValidatorSet{
		Validators: append(valset1, valset2...),
		Proposer:   valset1[0],
	}

	valsetProto, err := valset.ToProto()
	if err != nil {
		logger.Error("ToProto", "error", err)
		return
	}
	byteData, err = proto.Marshal(valsetProto)
	if err != nil {
		logger.Error("Marshal", "error", err)
		return
	}

	valset_proto := base64.RawStdEncoding.EncodeToString(byteData)
	logger.Info("", "encoded", len(valset_proto), "byte data", len(byteData), "url", url1)

	logger.Info("Validation",
		"ValidatorHash", hex.EncodeToString(signedHeader.Header.ValidatorsHash),
		"ValSetHash", hex.EncodeToString(valset.Hash()),
		"Equality", hex.EncodeToString(signedHeader.Header.ValidatorsHash) == hex.EncodeToString(valset.Hash()),
		"Length", len(valset.Validators),
	)

	//fmt.Println(header_proto)
	//fmt.Println(valset_proto)

	lightBlock := types.LightBlock{
		SignedHeader: signedHeader,
		ValidatorSet: &valset,
	}

	lightBlockProto, err := lightBlock.ToProto()
	if err != nil {
		logger.Error("LightToProto", "error", err)
		return
	}
	lightBlockData, err := proto.Marshal(lightBlockProto)
	if err != nil {
		logger.Error("Marshal", "error", err)
		return
	}

	lightBlockEncoded := base64.RawStdEncoding.EncodeToString(lightBlockData)
	fmt.Println(lightBlockEncoded)
	//sample := valset.Validators[0].Address
	//fmt.Println("[Oliver]", sample, len(sample), string(sample), string(valset.Validators[1].Address))
	//fmt.Println("[Oliver]", string(sample[31:]), len(sample[31:]))
	//prefix, address, err := DecodeAndConvert(string(sample))
	//fmt.Println("[Oliver]", prefix, address, string(address), len(address))
	//fmt.Println("[Oliver]", hex.DecodeString(valset.Validators[0].Address))
	logger.Info("", "encoded", len(lightBlockEncoded), "byte data", len(lightBlockData), "url", url1, "prefix", hex.EncodeToString(lightBlockData[:10]))
	logger.Info("Info", "Commit Height", signedHeader.Commit.Height, "Height", signedHeader.Height)

	pb := new(tmproto.LightBlock)

	err = proto.Unmarshal(lightBlockData, pb)
	if err != nil {
		logger.Error("Fail To Unmarshal", "Error", err)
		return
	}

	lb, err := types.LightBlockFromProto(pb)
	if err != nil {
		logger.Error("Fail To LightBlockFromProto", "Error", err)
		return
	}

	err = lb.SignedHeader.ValidateBasic(lb.SignedHeader.ChainID)
	if err != nil {
		logger.Error("Fail To ValidateBasic", "Error", err)
		return
	}

	err = types.VerifyCommitLight(lb.SignedHeader.ChainID, lb.ValidatorSet, lb.SignedHeader.Commit.BlockID, lb.SignedHeader.Height, lb.SignedHeader.Commit)
	if err != nil {
		logger.Error("Fail To Verify Commit Light", "Error", err)
		return
	}
}
