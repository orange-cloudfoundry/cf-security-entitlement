package client

func (c Client) BindSecurityGroup(secGroupGUID, spaceGUID string) error {

	listSpaceGUID := []string{spaceGUID}

	_, err := c.session.V3().UpdateSecurityGroupRunningSpace(secGroupGUID, listSpaceGUID)
	if err != nil {
		return err
	}

	c.BindStagingSecGroupToSpace(secGroupGUID, spaceGUID)

	return nil
}

func (c Client) UnbindSecurityGroup(secGroupGUID, spaceGUID string) error {

	_, err := c.session.V3().UnbindSecurityGroupRunningSpace(secGroupGUID, spaceGUID)
	if err != nil {
		return err
	}

	c.UnbindStagingSecGroupToSpace(secGroupGUID, spaceGUID)

	return nil
}

func (c Client) BindStagingSecGroupToSpace(secGroupGUID, spaceGUID string) error {

	listSpaceGUID := []string{spaceGUID}
	_, err := c.session.V3().UpdateSecurityGroupStagingSpace(secGroupGUID, listSpaceGUID)
	if err != nil {
		return err
	}

	return nil
}

func (c Client) UnbindStagingSecGroupToSpace(secGroupGUID, spaceGUID string) error {

	_, err := c.session.V3().UnbindSecurityGroupStagingSpace(secGroupGUID, spaceGUID)
	if err != nil {
		return err
	}

	return nil
}
