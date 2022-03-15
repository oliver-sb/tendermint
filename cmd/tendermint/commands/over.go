package commands

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/spf13/cobra"
	"github.com/tendermint/tendermint/internal/jsontypes"
	"github.com/tendermint/tendermint/libs/log"
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
		v.Address = []byte(val.Address)
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

func run(logger log.Logger) {
	logger.Info("Run Over")

	host := "https://lcd.terra.dev"
	//host := "http://localhost:1317"

	blockData := getData(host+"/blocks/latest", logger)
	signedHeader := getSignedHeader(blockData, logger)
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

	fmt.Println(header_proto)
	fmt.Println(valset_proto)
}
