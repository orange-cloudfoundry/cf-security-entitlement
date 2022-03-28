package client

func (c Client) BindSecurityGroup(secGroupGUID, spaceGUID string) error {

	listSpaceGUID := []string{spaceGUID}

	_, err := c.ccv3Client.UpdateSecurityGroupRunningSpace(secGroupGUID, listSpaceGUID)
	if err != nil {
		return err
	}

	c.BindStagingSecGroupToSpace(secGroupGUID, spaceGUID)

	return nil
}

func (c Client) UnbindSecurityGroup(secGroupGUID, spaceGUID string) error {

	_, err := c.ccv3Client.UnbindSecurityGroupRunningSpace(secGroupGUID, spaceGUID)
	if err != nil {
		return err
	}

	c.UnbindStagingSecGroupToSpace(secGroupGUID, spaceGUID)

	return nil
}

func (c Client) BindStagingSecGroupToSpace(secGroupGUID, spaceGUID string) error {

	listSpaceGUID := []string{spaceGUID}
	_, err := c.ccv3Client.UpdateSecurityGroupStagingSpace(secGroupGUID, listSpaceGUID)
	if err != nil {
		return err
	}

	return nil
}

func (c Client) UnbindStagingSecGroupToSpace(secGroupGUID, spaceGUID string) error {

	_, err := c.ccv3Client.UnbindSecurityGroupStagingSpace(secGroupGUID, spaceGUID)
	if err != nil {
		return err
	}

	return nil
}
